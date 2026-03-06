import { HistoryEntry, SequenceConfig, SequenceRule, Violation } from './types';

/**
 * Multi-step sequence safety engine.
 *
 * While per-action checks catch individual violations, sequence analysis
 * detects emergent unsafe patterns across multiple steps — the "slicing attack"
 * problem where individually-safe actions combine to produce an unsafe state.
 *
 * Supports:
 * - Sliding window invariants (check last N steps)
 * - Cumulative invariants (check entire session history)
 * - Max sequence length enforcement
 * - Pattern detection (repeated actions, oscillation, escalation)
 */
export class SequenceEnforcer {
  private config: SequenceConfig;

  constructor(config: SequenceConfig) {
    this.config = config;
  }

  check(history: HistoryEntry[]): Violation[] {
    const violations: Violation[] = [];
    const now = Date.now();

    // Max length check
    if (this.config.maxLength !== undefined && history.length >= this.config.maxLength) {
      violations.push({
        rule: 'sequence:max-length',
        severity: 'critical',
        message: `Sequence length ${history.length} exceeds maximum ${this.config.maxLength}`,
        phase: 'sequence',
        timestamp: now,
      });
    }

    // Check each sequence rule against history
    for (const rule of this.config.rules) {
      try {
        const passed = rule.check(history);
        if (!passed) {
          violations.push({
            rule: `sequence:${rule.name}`,
            severity: rule.severity,
            message: rule.description ?? `Sequence rule '${rule.name}' violated`,
            phase: 'sequence',
            timestamp: now,
          });
        }
      } catch {
        violations.push({
          rule: `sequence:${rule.name}`,
          severity: rule.severity,
          message: `Sequence rule '${rule.name}' threw an error during check`,
          phase: 'sequence',
          timestamp: now,
        });
      }
    }

    return violations;
  }
}

// ── Built-in sequence rules ─────────────────────────────────────────────────

/**
 * Detects repeated identical outputs — a sign the agent is stuck in a loop.
 */
export function noRepeatLoop(windowSize: number = 5, maxRepeats: number = 3): SequenceRule {
  return {
    name: 'no-repeat-loop',
    description: `No more than ${maxRepeats} identical outputs in last ${windowSize} steps`,
    severity: 'warning',
    check: (history: HistoryEntry[]) => {
      if (history.length < maxRepeats) return true;
      const window = history.slice(-windowSize);
      const outputs = window.map(h => JSON.stringify(h.output));
      const counts = new Map<string, number>();
      for (const o of outputs) {
        counts.set(o, (counts.get(o) ?? 0) + 1);
      }
      for (const count of counts.values()) {
        if (count >= maxRepeats) return false;
      }
      return true;
    },
  };
}

/**
 * Detects escalating violation rates — each window has more violations than the last.
 */
export function noEscalation(windowSize: number = 5, maxConsecutiveIncreases: number = 3): SequenceRule {
  return {
    name: 'no-escalation',
    description: `Violation rate must not increase ${maxConsecutiveIncreases} consecutive windows`,
    severity: 'warning',
    check: (history: HistoryEntry[]) => {
      if (history.length < windowSize * 2) return true;

      // Split into windows and count violations per window
      const windowCount = Math.floor(history.length / windowSize);
      const rates: number[] = [];
      for (let i = 0; i < windowCount; i++) {
        const start = i * windowSize;
        const window = history.slice(start, start + windowSize);
        const violations = window.filter(h => h.decision.violations.length > 0).length;
        rates.push(violations / windowSize);
      }

      // Check for consecutive increases
      let increases = 0;
      for (let i = 1; i < rates.length; i++) {
        if (rates[i] > rates[i - 1]) {
          increases++;
          if (increases >= maxConsecutiveIncreases) return false;
        } else {
          increases = 0;
        }
      }
      return true;
    },
  };
}

/**
 * Ensures cumulative cost across the sequence stays within a total budget.
 */
export function maxCumulativeCost(maxCost: number): SequenceRule {
  return {
    name: 'max-cumulative-cost',
    description: `Cumulative cost must not exceed $${maxCost}`,
    severity: 'critical',
    check: (history: HistoryEntry[]) => {
      const totalCost = history.reduce((sum, h) => {
        const costViolation = h.decision.budgetSnapshot.cost.used;
        return costViolation;
      }, 0);
      // Get cost from the last entry's budget snapshot (it's cumulative)
      if (history.length === 0) return true;
      const lastCost = history[history.length - 1].decision.budgetSnapshot.cost.used;
      return lastCost <= maxCost;
    },
  };
}

/**
 * Detects oscillation — output alternating between two states,
 * indicating the agent is indecisive or in a feedback loop.
 */
export function noOscillation(minOscillations: number = 4): SequenceRule {
  return {
    name: 'no-oscillation',
    description: `Output must not oscillate between two states ${minOscillations}+ times`,
    severity: 'warning',
    check: (history: HistoryEntry[]) => {
      if (history.length < minOscillations * 2) return true;
      const outputs = history.slice(-minOscillations * 2).map(h => JSON.stringify(h.output));

      // Check if outputs alternate: A, B, A, B, A, B...
      if (outputs.length < 4) return true;
      const a = outputs[0];
      const b = outputs[1];
      if (a === b) return true;

      let alternating = 0;
      for (let i = 0; i < outputs.length; i++) {
        const expected = i % 2 === 0 ? a : b;
        if (outputs[i] === expected) {
          alternating++;
        } else {
          break;
        }
      }
      return alternating < minOscillations * 2;
    },
  };
}
