import {
  BudgetConfig, BudgetSnapshot, Violation, DegradationThreshold,
} from './types';

export class BudgetEnforcer {
  private tokensUsed = 0;
  private costIncurred = 0;
  private actionsUsed = 0;
  private startTime: number;
  private config: BudgetConfig;

  constructor(config: BudgetConfig) {
    this.config = config;
    this.startTime = Date.now();
  }

  check(): Violation[] {
    const violations: Violation[] = [];
    const now = Date.now();

    if (this.config.maxTokens !== undefined && this.tokensUsed >= this.config.maxTokens) {
      violations.push({
        rule: 'budget:tokens',
        severity: 'critical',
        message: `Token budget exhausted: ${this.tokensUsed}/${this.config.maxTokens}`,
        phase: 'budget',
        timestamp: now,
      });
    }

    if (this.config.maxCost !== undefined && this.costIncurred >= this.config.maxCost) {
      violations.push({
        rule: 'budget:cost',
        severity: 'critical',
        message: `Cost budget exhausted: $${this.costIncurred.toFixed(4)}/$${this.config.maxCost.toFixed(4)}`,
        phase: 'budget',
        timestamp: now,
      });
    }

    if (this.config.maxActions !== undefined && this.actionsUsed >= this.config.maxActions) {
      violations.push({
        rule: 'budget:actions',
        severity: 'critical',
        message: `Action budget exhausted: ${this.actionsUsed}/${this.config.maxActions}`,
        phase: 'budget',
        timestamp: now,
      });
    }

    if (this.config.maxDurationMs !== undefined) {
      const elapsed = now - this.startTime;
      if (elapsed >= this.config.maxDurationMs) {
        violations.push({
          rule: 'budget:duration',
          severity: 'critical',
          message: `Duration budget exhausted: ${elapsed}ms/${this.config.maxDurationMs}ms`,
          phase: 'budget',
          timestamp: now,
        });
      }
    }

    return violations;
  }

  checkLatency(latencyMs: number): Violation | null {
    if (this.config.maxLatencyMs !== undefined && latencyMs > this.config.maxLatencyMs) {
      return {
        rule: 'budget:latency',
        severity: 'warning',
        message: `Latency exceeded: ${latencyMs.toFixed(0)}ms/${this.config.maxLatencyMs}ms`,
        phase: 'budget',
        timestamp: Date.now(),
      };
    }
    return null;
  }

  record(tokens?: number, cost?: number): void {
    if (tokens !== undefined) this.tokensUsed += tokens;
    if (cost !== undefined) this.costIncurred += cost;
    this.actionsUsed++;
  }

  snapshot(): BudgetSnapshot {
    const now = Date.now();
    const durationMs = now - this.startTime;

    const tokenPercent = this.config.maxTokens
      ? (this.tokensUsed / this.config.maxTokens) * 100 : 0;
    const costPercent = this.config.maxCost
      ? (this.costIncurred / this.config.maxCost) * 100 : 0;
    const actionPercent = this.config.maxActions
      ? (this.actionsUsed / this.config.maxActions) * 100 : 0;
    const durationPercent = this.config.maxDurationMs
      ? (durationMs / this.config.maxDurationMs) * 100 : 0;

    const maxPercent = Math.max(tokenPercent, costPercent, actionPercent, durationPercent);
    const activeDegradations = this.getActiveDegradations(maxPercent);

    let status: BudgetSnapshot['status'] = 'ok';
    if (maxPercent >= 100) status = 'exhausted';
    else if (maxPercent >= 90) status = 'critical';
    else if (maxPercent >= 75) status = 'warning';

    return {
      tokens: { used: this.tokensUsed, limit: this.config.maxTokens, percent: tokenPercent },
      cost: { used: this.costIncurred, limit: this.config.maxCost, percent: costPercent },
      actions: { used: this.actionsUsed, limit: this.config.maxActions, percent: actionPercent },
      duration: { usedMs: durationMs, limit: this.config.maxDurationMs, percent: durationPercent },
      status,
      activeDegradations,
    };
  }

  shouldBlock(): boolean {
    const strategy = this.config.degradation ?? 'hard-stop';
    if (strategy === 'warn') return false;
    const violations = this.check();
    return violations.some(v => v.severity === 'critical');
  }

  private getActiveDegradations(maxPercent: number): string[] {
    const thresholds = this.config.degradationThresholds;
    if (!thresholds || thresholds.length === 0) return [];

    const sorted = [...thresholds].sort((a, b) => b.percent - a.percent);
    const active: string[] = [];
    for (const t of sorted) {
      if (maxPercent >= t.percent) {
        active.push(t.message ?? `${t.action} at ${t.percent}%`);
      }
    }
    return active;
  }

  reset(): void {
    this.tokensUsed = 0;
    this.costIncurred = 0;
    this.actionsUsed = 0;
    this.startTime = Date.now();
  }

  getTokensUsed(): number { return this.tokensUsed; }
  getCostIncurred(): number { return this.costIncurred; }
  getActionsUsed(): number { return this.actionsUsed; }
  getElapsedMs(): number { return Date.now() - this.startTime; }
}
