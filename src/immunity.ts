/**
 * Adaptive Immune System for AI Agents.
 *
 * Biological analogy:
 *   Innate immunity  = static contract rules (preconditions, postconditions)
 *   Adaptive immunity = THIS MODULE (learned responses, threat memory, antibodies)
 *
 * The immune system:
 *   1. Learns the agent's normal behavioral signature (learning phase)
 *   2. Detects anomalous behavior in real-time (active immunity)
 *   3. Remembers confirmed threats (threat memory)
 *   4. Shares threat patterns across agents (antibody export/import)
 */

import { createHash } from 'crypto';
import { ImmuneResponse, ThreatRecord, Antibody, ImmuneStatus } from './types';

// ── Internal types ──────────────────────────────────────────────────────────

interface RunningStats {
  mean: number;
  m2: number;   // sum of squared differences (Welford's)
  n: number;
}

interface BehavioralSignature {
  inputPatterns: Record<string, number>;
  outputPatterns: Record<string, number>;
  actionSequences: Record<string, number>;
  latencyStats: RunningStats;
  violationStats: RunningStats;
  established: boolean;
  sampleCount: number;
}

// ── Immune System ───────────────────────────────────────────────────────────

export class ImmuneSystem {
  private signature: BehavioralSignature;
  private threats: Map<string, ThreatRecord> = new Map();
  private antibodies: Map<string, Antibody> = new Map();
  private learningPeriod: number;
  private sequenceWindow: number;
  private recentInputHashes: string[] = [];

  constructor(opts: { learningPeriod?: number; sequenceWindow?: number } = {}) {
    this.learningPeriod = opts.learningPeriod ?? 20;
    this.sequenceWindow = opts.sequenceWindow ?? 3;
    this.signature = this.freshSignature();
  }

  /**
   * Evaluate an action and return an immune response.
   * Called BEFORE the agent executes (for early threat detection)
   * and AFTER (with full context for learning).
   */
  evaluate(
    input: any,
    output: any,
    violations: string[],
    latencyMs: number,
  ): ImmuneResponse {
    const contentHash = this.contentHash(input);
    const shapeHash = this.shapeHash(input);

    // 1. Check known threats (exact content match)
    const knownThreat = this.threats.get(contentHash);
    if (knownThreat) {
      knownThreat.lastSeen = Date.now();
      knownThreat.occurrences++;
      return {
        threat: true,
        confidence: Math.min(0.5 + knownThreat.occurrences * 0.1, 0.99),
        threatType: 'known',
        response: knownThreat.severity === 'critical' ? 'block' : 'quarantine',
        explanation: `Known threat pattern (seen ${knownThreat.occurrences} times): ${knownThreat.inputShape}`,
        newThreat: false,
      };
    }

    // 2. Check imported antibodies
    const antibodyMatch = this.antibodies.get(contentHash);
    if (antibodyMatch) {
      antibodyMatch.uses++;
      return {
        threat: true,
        confidence: antibodyMatch.effectiveness,
        threatType: 'known',
        response: 'quarantine',
        explanation: `Antibody match: ${antibodyMatch.description}`,
        newThreat: false,
      };
    }

    // 3. Learning phase — build baseline
    if (!this.signature.established) {
      this.learn(shapeHash, this.shapeHash(output), violations.length, latencyMs);
      return {
        threat: false,
        confidence: 0,
        threatType: 'none',
        response: 'allow',
        explanation: `Learning phase (${this.signature.sampleCount}/${this.learningPeriod})`,
        newThreat: false,
      };
    }

    // 4. Active immunity — anomaly detection
    const anomalyScore = this.computeAnomalyScore(
      shapeHash, this.shapeHash(output), violations.length, latencyMs,
    );

    // Continue learning (slow adaptation)
    this.learn(shapeHash, this.shapeHash(output), violations.length, latencyMs);

    if (anomalyScore > 0.8) {
      return {
        threat: true,
        confidence: anomalyScore,
        threatType: 'anomaly',
        response: anomalyScore > 0.95 ? 'block' : 'quarantine',
        explanation: `Behavioral anomaly detected (score: ${anomalyScore.toFixed(3)})`,
        newThreat: true,
      };
    }

    return {
      threat: false,
      confidence: 1 - anomalyScore,
      threatType: 'none',
      response: 'allow',
      explanation: 'Normal behavioral pattern',
      newThreat: false,
    };
  }

  /** Record a confirmed threat (called when contract enforcement blocks an action). */
  recordThreat(
    input: any,
    severity: 'critical' | 'warning' | 'info',
  ): void {
    const hash = this.contentHash(input);
    const existing = this.threats.get(hash);

    if (existing) {
      existing.lastSeen = Date.now();
      existing.occurrences++;
      if (severity === 'critical') existing.severity = 'critical';
    } else {
      this.threats.set(hash, {
        id: `threat-${Date.now().toString(36)}-${this.threats.size}`,
        pattern: hash,
        inputShape: this.describeShape(input),
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        occurrences: 1,
        severity,
      });
    }
  }

  /** Export confirmed threat patterns as antibodies for other agents. */
  exportAntibodies(agentId: string): Antibody[] {
    const result: Antibody[] = [];
    for (const [, threat] of this.threats) {
      if (threat.occurrences >= 2) {
        result.push({
          id: `ab-${threat.id}`,
          pattern: threat.pattern,
          description: `${threat.severity} threat: ${threat.inputShape}`,
          source: agentId,
          effectiveness: Math.min(0.5 + threat.occurrences * 0.1, 0.95),
          created: Date.now(),
          uses: 0,
        });
      }
    }
    return result;
  }

  /** Import antibodies from another agent's immune system. */
  importAntibodies(antibodies: Antibody[]): number {
    let imported = 0;
    for (const ab of antibodies) {
      if (!this.antibodies.has(ab.pattern)) {
        this.antibodies.set(ab.pattern, { ...ab });
        imported++;
      }
    }
    return imported;
  }

  /** Get current immune system status. */
  getStatus(): ImmuneStatus {
    const vStats = this.signature.violationStats;
    const lStats = this.signature.latencyStats;
    return {
      established: this.signature.established,
      sampleCount: this.signature.sampleCount,
      knownThreats: this.threats.size,
      antibodyCount: this.antibodies.size,
      baseline: {
        avgViolationRate: vStats.mean,
        avgLatency: lStats.mean,
        patternCount: Object.keys(this.signature.inputPatterns).length,
      },
    };
  }

  getThreats(): ThreatRecord[] {
    return Array.from(this.threats.values());
  }

  getAntibodies(): Antibody[] {
    return Array.from(this.antibodies.values());
  }

  reset(): void {
    this.signature = this.freshSignature();
    this.threats.clear();
    this.antibodies.clear();
    this.recentInputHashes = [];
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private freshSignature(): BehavioralSignature {
    return {
      inputPatterns: {},
      outputPatterns: {},
      actionSequences: {},
      latencyStats: { mean: 0, m2: 0, n: 0 },
      violationStats: { mean: 0, m2: 0, n: 0 },
      established: false,
      sampleCount: 0,
    };
  }

  private learn(
    inputHash: string,
    outputHash: string,
    violationCount: number,
    latencyMs: number,
  ): void {
    this.signature.sampleCount++;

    // Track pattern frequencies
    this.signature.inputPatterns[inputHash] =
      (this.signature.inputPatterns[inputHash] ?? 0) + 1;
    this.signature.outputPatterns[outputHash] =
      (this.signature.outputPatterns[outputHash] ?? 0) + 1;

    // Track action sequences
    this.recentInputHashes.push(inputHash);
    if (this.recentInputHashes.length > this.sequenceWindow) {
      this.recentInputHashes.shift();
    }
    if (this.recentInputHashes.length >= 2) {
      const seq = this.recentInputHashes.join('>');
      this.signature.actionSequences[seq] =
        (this.signature.actionSequences[seq] ?? 0) + 1;
    }

    // Welford's online algorithm for running mean + variance
    this.welfordUpdate(this.signature.latencyStats, latencyMs);
    this.welfordUpdate(this.signature.violationStats, violationCount);

    if (this.signature.sampleCount >= this.learningPeriod) {
      this.signature.established = true;
    }
  }

  private welfordUpdate(stats: RunningStats, value: number): void {
    stats.n++;
    const delta = value - stats.mean;
    stats.mean += delta / stats.n;
    const delta2 = value - stats.mean;
    stats.m2 += delta * delta2;
  }

  private getStddev(stats: RunningStats): number {
    if (stats.n < 2) return 0;
    return Math.sqrt(stats.m2 / (stats.n - 1));
  }

  private computeAnomalyScore(
    inputHash: string,
    outputHash: string,
    violationCount: number,
    latencyMs: number,
  ): number {
    const scores: number[] = [];

    // 1. Input novelty — never-seen structural patterns score high
    const inputFreq = this.signature.inputPatterns[inputHash] ?? 0;
    scores.push(inputFreq === 0 ? 0.6 : 0);

    // 2. Output novelty
    const outputFreq = this.signature.outputPatterns[outputHash] ?? 0;
    scores.push(outputFreq === 0 ? 0.4 : 0);

    // 3. Violation rate anomaly (z-score)
    const vStddev = this.getStddev(this.signature.violationStats);
    if (vStddev > 0) {
      const z = (violationCount - this.signature.violationStats.mean) / vStddev;
      scores.push(Math.min(Math.max(z / 3, 0), 1));
    }

    // 4. Latency anomaly (z-score)
    const lStddev = this.getStddev(this.signature.latencyStats);
    if (lStddev > 0) {
      const z = (latencyMs - this.signature.latencyStats.mean) / lStddev;
      scores.push(Math.min(Math.max(z / 3, 0), 1));
    }

    // 5. Sequence novelty — action sequence never seen before
    if (this.recentInputHashes.length >= 2) {
      const seq = this.recentInputHashes.join('>');
      const seqFreq = this.signature.actionSequences[seq] ?? 0;
      scores.push(seqFreq === 0 ? 0.3 : 0);
    }

    return scores.length > 0 ? Math.max(...scores) : 0;
  }

  /** SHA-256 of the full serialized content — for exact threat matching. */
  private contentHash(value: any): string {
    const serialized = JSON.stringify(value) ?? 'undefined';
    return createHash('sha256').update(serialized).digest('hex').slice(0, 32);
  }

  /** SHA-256 of the structural shape — for behavioral profiling. */
  private shapeHash(value: any): string {
    const shape = this.describeShape(value);
    return createHash('sha256').update(shape).digest('hex').slice(0, 16);
  }

  /** Describe the structural shape of a value (type + structure, not content). */
  private describeShape(value: any): string {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'string') return `string(${value.length})`;
    if (typeof value === 'number') return 'number';
    if (typeof value === 'boolean') return 'boolean';
    if (Array.isArray(value)) {
      const itemShapes = value.slice(0, 3).map(v => this.describeShape(v));
      return `array(${value.length})[${itemShapes.join(',')}]`;
    }
    if (typeof value === 'object') {
      const keys = Object.keys(value).sort();
      return `{${keys.join(',')}}`;
    }
    return typeof value;
  }
}
