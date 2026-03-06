import {
  AgentFn, Contract, Decision, Violation, HistoryEntry,
  SessionState, SessionMetrics, HarnessedAgent, CallOptions,
  BudgetSnapshot, RuleContext, SequenceConfig, DriftConfig,
} from './types';
import { BudgetEnforcer } from './budget';
import { DriftMonitor } from './monitor';
import { SequenceEnforcer } from './sequence';
import { Auditor } from './audit';

let sessionCounter = 0;

export function createHarnessedAgent(
  agent: AgentFn,
  contract: Contract & { sequenceConfig?: SequenceConfig },
  driftConfig?: Partial<DriftConfig>,
): HarnessedAgent {
  const sessionId = `session-${++sessionCounter}-${Date.now().toString(36)}`;
  let state: SessionState = {};
  let history: HistoryEntry[] = [];
  let totalLatency = 0;

  const metrics: SessionMetrics = {
    totalCalls: 0,
    totalViolations: 0,
    totalBlocked: 0,
    totalRecovered: 0,
    violationRate: 0,
    blockRate: 0,
    avgLatencyMs: 0,
    totalTokens: 0,
    totalCost: 0,
    startTime: Date.now(),
    lastCallTime: Date.now(),
    driftScore: 0,
  };

  const budget = contract.budget ? new BudgetEnforcer(contract.budget) : null;
  const monitor = new DriftMonitor(driftConfig);
  const sequencer = contract.sequenceConfig
    ? new SequenceEnforcer(contract.sequenceConfig) : null;
  const auditor = new Auditor(sessionId, contract.name);

  function buildContext(input: any, output?: any): RuleContext {
    return { input, output, state, history, metrics };
  }

  async function checkRules(rules: Array<{ name: string; check: (ctx: RuleContext) => boolean | Promise<boolean>; severity: 'critical' | 'warning' | 'info' }>, ctx: RuleContext, phase: Violation['phase']): Promise<Violation[]> {
    const violations: Violation[] = [];
    for (const rule of rules) {
      try {
        const passed = await rule.check(ctx);
        if (!passed) {
          violations.push({
            rule: rule.name,
            severity: rule.severity,
            message: `${phase} '${rule.name}' failed`,
            phase,
            timestamp: Date.now(),
          });
        }
      } catch (err) {
        violations.push({
          rule: rule.name,
          severity: rule.severity,
          message: `${phase} '${rule.name}' threw: ${err instanceof Error ? err.message : String(err)}`,
          phase,
          timestamp: Date.now(),
        });
      }
    }
    return violations;
  }

  async function executeOnce(input: any, opts?: CallOptions): Promise<{ output: any; violations: Violation[]; latencyMs: number }> {
    const allViolations: Violation[] = [];

    // ── Budget gate (structural: exhausted budget = unreachable) ──
    if (budget) {
      const budgetViolations = budget.check();
      if (budgetViolations.length > 0 && budget.shouldBlock()) {
        return { output: undefined, violations: budgetViolations, latencyMs: 0 };
      }
      allViolations.push(...budgetViolations.filter(v => v.severity !== 'critical'));
    }

    // ── Sequence gate ──
    if (sequencer) {
      const seqViolations = sequencer.check(history);
      const critical = seqViolations.filter(v => v.severity === 'critical');
      if (critical.length > 0) {
        return { output: undefined, violations: seqViolations, latencyMs: 0 };
      }
      allViolations.push(...seqViolations.filter(v => v.severity !== 'critical'));
    }

    // ── Preconditions ──
    const preCtx = buildContext(input);
    const preViolations = await checkRules(contract.preconditions, preCtx, 'precondition');
    const criticalPre = preViolations.filter(v => v.severity === 'critical');
    if (criticalPre.length > 0) {
      return { output: undefined, violations: [...allViolations, ...preViolations], latencyMs: 0 };
    }
    allViolations.push(...preViolations);

    // ── Execute agent ──
    const start = Date.now();
    let output: any;
    let agentTokens: number | undefined;
    let agentCost: number | undefined;
    try {
      output = await agent(input);
    } catch (err) {
      allViolations.push({
        rule: 'agent:exception',
        severity: 'critical',
        message: `Agent threw: ${err instanceof Error ? err.message : String(err)}`,
        phase: 'postcondition',
        timestamp: Date.now(),
      });
      return { output: undefined, violations: allViolations, latencyMs: Date.now() - start };
    }
    const latencyMs = Date.now() - start;

    // ── Extract enriched output from adapters ──
    if (output && typeof output === 'object' && output.__bulwark === true) {
      agentTokens = output.tokensUsed;
      agentCost = output.costIncurred;
      output = output.output;
    }

    // ── Latency check ──
    if (budget) {
      const latViolation = budget.checkLatency(latencyMs);
      if (latViolation) allViolations.push(latViolation);
    }

    // ── Postconditions ──
    const postCtx = buildContext(input, output);
    const postViolations = await checkRules(contract.postconditions, postCtx, 'postcondition');
    allViolations.push(...postViolations);

    // ── Invariants ──
    const invViolations = await checkRules(contract.invariants, postCtx, 'invariant');
    allViolations.push(...invViolations);

    // ── Record budget usage (adapter auto-tracking takes precedence) ──
    if (budget) {
      budget.record(opts?.tokensUsed ?? agentTokens, opts?.costIncurred ?? agentCost);
    }

    return { output, violations: allViolations, latencyMs };
  }

  async function call(input: any, opts?: CallOptions): Promise<Decision> {
    // Apply call-level state overrides
    if (opts?.state) {
      Object.assign(state, opts.state);
    }

    const recovery = contract.recovery;
    let attempts = 0;
    let usedFallback = false;
    let lastResult = await executeOnce(input, opts);
    attempts++;

    const hasCritical = (v: Violation[]) => v.some(vi => vi.severity === 'critical');

    // ── Recovery loop ──
    if (hasCritical(lastResult.violations) && recovery) {
      if (recovery.strategy === 'retry' && recovery.maxRetries) {
        while (attempts <= recovery.maxRetries && hasCritical(lastResult.violations)) {
          // Notify violation handler
          if (recovery.onViolation) {
            for (const v of lastResult.violations) recovery.onViolation(v);
          }
          if (recovery.retryDelayMs) {
            await new Promise(r => setTimeout(r, recovery.retryDelayMs));
          }
          lastResult = await executeOnce(input, opts);
          attempts++;
        }
        if (!hasCritical(lastResult.violations)) {
          metrics.totalRecovered++;
        }
      } else if (recovery.strategy === 'fallback' && recovery.fallbackFn) {
        try {
          const fallbackOutput = await recovery.fallbackFn(input, lastResult.violations);
          lastResult = {
            output: fallbackOutput,
            violations: lastResult.violations.map(v => ({ ...v, severity: 'info' as const })),
            latencyMs: lastResult.latencyMs,
          };
          metrics.totalRecovered++;
          usedFallback = true;
        } catch {
          // Fallback itself failed; keep original violations
        }
      }
      // 'block' strategy: do nothing, violations stand
    }

    const allowed = !hasCritical(lastResult.violations);
    const budgetSnapshot = budget?.snapshot() ?? {
      tokens: { used: 0, limit: undefined, percent: 0 },
      cost: { used: 0, limit: undefined, percent: 0 },
      actions: { used: 0, limit: undefined, percent: 0 },
      duration: { usedMs: 0, limit: undefined, percent: 0 },
      status: 'ok' as const,
      activeDegradations: [],
    };

    const decision: Decision = {
      allowed,
      output: allowed ? lastResult.output : undefined,
      violations: lastResult.violations,
      latencyMs: lastResult.latencyMs,
      recovered: (attempts > 1 || usedFallback) && allowed,
      recoveryAttempts: attempts - 1,
      budgetSnapshot,
    };

    // ── Update session state ──
    const entry: HistoryEntry = {
      timestamp: Date.now(),
      input,
      output: lastResult.output,
      decision,
      sequenceIndex: history.length,
    };
    history.push(entry);

    // ── Update metrics ──
    metrics.totalCalls++;
    metrics.totalViolations += lastResult.violations.length;
    if (!allowed) metrics.totalBlocked++;
    metrics.violationRate = metrics.totalViolations / metrics.totalCalls;
    metrics.blockRate = metrics.totalBlocked / metrics.totalCalls;
    totalLatency += lastResult.latencyMs;
    metrics.avgLatencyMs = totalLatency / metrics.totalCalls;
    if (opts?.tokensUsed) metrics.totalTokens += opts.tokensUsed;
    if (opts?.costIncurred) metrics.totalCost += opts.costIncurred;
    metrics.lastCallTime = Date.now();

    // ── Update drift monitor ──
    monitor.record(lastResult.violations.length > 0);
    metrics.driftScore = monitor.getDrift().score;

    // ── Update audit log ──
    auditor.record(entry);

    return decision;
  }

  return {
    call,
    getMetrics: () => ({ ...metrics }),
    getDrift: () => monitor.getDrift(),
    getAudit: () => auditor.report(
      budget?.snapshot() ?? {
        tokens: { used: 0, limit: undefined, percent: 0 },
        cost: { used: 0, limit: undefined, percent: 0 },
        actions: { used: 0, limit: undefined, percent: 0 },
        duration: { usedMs: 0, limit: undefined, percent: 0 },
        status: 'ok' as const,
        activeDegradations: [],
      },
      monitor,
    ),
    getBudget: () => budget?.snapshot() ?? {
      tokens: { used: 0, limit: undefined, percent: 0 },
      cost: { used: 0, limit: undefined, percent: 0 },
      actions: { used: 0, limit: undefined, percent: 0 },
      duration: { usedMs: 0, limit: undefined, percent: 0 },
      status: 'ok' as const,
      activeDegradations: [],
    },
    getHistory: () => [...history],
    setState: (key: string, value: any) => { state[key] = value; },
    getState: () => ({ ...state }),
    reset: () => {
      state = {};
      history = [];
      totalLatency = 0;
      metrics.totalCalls = 0;
      metrics.totalViolations = 0;
      metrics.totalBlocked = 0;
      metrics.totalRecovered = 0;
      metrics.violationRate = 0;
      metrics.blockRate = 0;
      metrics.avgLatencyMs = 0;
      metrics.totalTokens = 0;
      metrics.totalCost = 0;
      metrics.startTime = Date.now();
      metrics.lastCallTime = Date.now();
      metrics.driftScore = 0;
      budget?.reset();
      monitor.reset();
      auditor.reset();
    },
    sessionId,
    contract,
  };
}
