import {
  AuditEntry, AuditReport, BudgetSnapshot, Decision,
  DriftResult, HistoryEntry, Severity,
} from './types';
import { DriftMonitor } from './monitor';

export class Auditor {
  private entries: AuditEntry[] = [];
  private sessionId: string;
  private contractName: string;
  private startTime: number;
  private driftSnapshots: DriftResult[] = [];

  constructor(sessionId: string, contractName: string) {
    this.sessionId = sessionId;
    this.contractName = contractName;
    this.startTime = Date.now();
  }

  record(entry: HistoryEntry): void {
    this.entries.push({
      timestamp: entry.timestamp,
      sessionId: this.sessionId,
      sequenceIndex: entry.sequenceIndex,
      contractName: this.contractName,
      input: entry.input,
      output: entry.output,
      decision: entry.decision,
    });
  }

  snapshotDrift(monitor: DriftMonitor): void {
    this.driftSnapshots.push(monitor.getDrift());
  }

  report(budgetSnapshot: BudgetSnapshot, monitor: DriftMonitor): AuditReport {
    const now = Date.now();
    const totalActions = this.entries.length;
    const violationEntries = this.entries.filter(e => e.decision.violations.length > 0);
    const blockedEntries = this.entries.filter(e => !e.decision.allowed);

    // Violation counts by rule
    const violationsByRule: Record<string, number> = {};
    const violationsBySeverity: Record<Severity, number> = {
      critical: 0, warning: 0, info: 0,
    };

    for (const entry of this.entries) {
      for (const v of entry.decision.violations) {
        violationsByRule[v.rule] = (violationsByRule[v.rule] ?? 0) + 1;
        violationsBySeverity[v.severity]++;
      }
    }

    const complianceRate = totalActions > 0
      ? ((totalActions - blockedEntries.length) / totalActions) * 100
      : 100;

    // Take a drift snapshot for the report
    this.snapshotDrift(monitor);

    const summary = this.generateSummary(
      totalActions,
      violationEntries.length,
      blockedEntries.length,
      complianceRate,
      violationsByRule,
      budgetSnapshot,
    );

    return {
      sessionId: this.sessionId,
      contractName: this.contractName,
      startTime: this.startTime,
      endTime: now,
      totalActions,
      totalViolations: violationEntries.length,
      totalBlocked: blockedEntries.length,
      complianceRate,
      budgetUsage: budgetSnapshot,
      driftHistory: [...this.driftSnapshots],
      violationsByRule,
      violationsBySeverity,
      timeline: [...this.entries],
      summary,
    };
  }

  private generateSummary(
    totalActions: number,
    totalViolations: number,
    totalBlocked: number,
    complianceRate: number,
    violationsByRule: Record<string, number>,
    budget: BudgetSnapshot,
  ): string {
    const lines: string[] = [];

    lines.push(`AUDIT REPORT: ${this.contractName}`);
    lines.push(`Session: ${this.sessionId}`);
    lines.push(`Period: ${new Date(this.startTime).toISOString()} — ${new Date().toISOString()}`);
    lines.push('');

    // Compliance
    lines.push(`COMPLIANCE: ${complianceRate.toFixed(1)}%`);
    lines.push(`  Actions: ${totalActions} total, ${totalBlocked} blocked, ${totalViolations} with violations`);

    // Top violations
    const sorted = Object.entries(violationsByRule)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);
    if (sorted.length > 0) {
      lines.push('');
      lines.push('TOP VIOLATIONS:');
      for (const [rule, count] of sorted) {
        lines.push(`  ${rule}: ${count} occurrence${count > 1 ? 's' : ''}`);
      }
    }

    // Budget
    if (budget.status !== 'ok') {
      lines.push('');
      lines.push(`BUDGET STATUS: ${budget.status.toUpperCase()}`);
      if (budget.tokens.limit) lines.push(`  Tokens: ${budget.tokens.used}/${budget.tokens.limit} (${budget.tokens.percent.toFixed(1)}%)`);
      if (budget.cost.limit) lines.push(`  Cost: $${budget.cost.used.toFixed(4)}/$${budget.cost.limit.toFixed(4)} (${budget.cost.percent.toFixed(1)}%)`);
      if (budget.actions.limit) lines.push(`  Actions: ${budget.actions.used}/${budget.actions.limit} (${budget.actions.percent.toFixed(1)}%)`);
    }

    // Drift
    const lastDrift = this.driftSnapshots[this.driftSnapshots.length - 1];
    if (lastDrift && lastDrift.alert) {
      lines.push('');
      lines.push(`DRIFT ALERT: score=${lastDrift.score.toFixed(3)}, trending=${lastDrift.trending}`);
    }

    // Verdict
    lines.push('');
    if (complianceRate >= 99) lines.push('VERDICT: EXCELLENT — Agent operating within contract bounds.');
    else if (complianceRate >= 95) lines.push('VERDICT: GOOD — Minor violations detected, within acceptable range.');
    else if (complianceRate >= 80) lines.push('VERDICT: CONCERNING — Significant violation rate, review contract or agent.');
    else lines.push('VERDICT: FAILING — Agent frequently violating contract. Immediate attention required.');

    return lines.join('\n');
  }

  reset(): void {
    this.entries = [];
    this.driftSnapshots = [];
    this.startTime = Date.now();
  }
}
