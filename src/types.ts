// ── Agent type ──────────────────────────────────────────────────────────────
export type AgentFn = (input: any) => any | Promise<any>;

// ── Rules ───────────────────────────────────────────────────────────────────
export interface RuleContext {
  input: any;
  output?: any;
  state: SessionState;
  history: HistoryEntry[];
  metrics: SessionMetrics;
}

export type RuleCheck = (ctx: RuleContext) => boolean | Promise<boolean>;

export type Severity = 'critical' | 'warning' | 'info';

export interface Rule {
  name: string;
  description?: string;
  severity: Severity;
  check: RuleCheck;
}

// ── Violations ──────────────────────────────────────────────────────────────
export interface Violation {
  rule: string;
  severity: Severity;
  message: string;
  phase: 'precondition' | 'postcondition' | 'invariant' | 'budget' | 'sequence';
  timestamp: number;
}

// ── Budget ──────────────────────────────────────────────────────────────────
export type DegradationStrategy = 'hard-stop' | 'warn' | 'degrade';

export interface BudgetConfig {
  maxTokens?: number;
  maxCost?: number;
  maxLatencyMs?: number;
  maxActions?: number;
  maxDurationMs?: number;
  degradation?: DegradationStrategy;
  degradationThresholds?: DegradationThreshold[];
}

export interface DegradationThreshold {
  percent: number;
  action: 'warn' | 'throttle' | 'simplify' | 'stop';
  message?: string;
}

export interface BudgetSnapshot {
  tokens: { used: number; limit?: number; percent: number };
  cost: { used: number; limit?: number; percent: number };
  actions: { used: number; limit?: number; percent: number };
  duration: { usedMs: number; limit?: number; percent: number };
  status: 'ok' | 'warning' | 'critical' | 'exhausted';
  activeDegradations: string[];
}

// ── Recovery ────────────────────────────────────────────────────────────────
export interface RecoveryConfig {
  strategy: 'block' | 'retry' | 'fallback';
  maxRetries?: number;
  retryDelayMs?: number;
  fallbackFn?: (input: any, violations: Violation[]) => any | Promise<any>;
  onViolation?: (violation: Violation) => void;
}

// ── Contract ────────────────────────────────────────────────────────────────
export interface Contract {
  name: string;
  description?: string;
  preconditions: Rule[];
  postconditions: Rule[];
  invariants: Rule[];
  budget?: BudgetConfig;
  recovery?: RecoveryConfig;
  inputSchema?: InputSchema;
}

export interface InputSchema {
  type: string;
  properties?: Record<string, SchemaProperty>;
  required?: string[];
}

export interface SchemaProperty {
  type: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  enum?: any[];
  pattern?: string;
}

// ── Session ─────────────────────────────────────────────────────────────────
export type SessionState = Record<string, any>;

export interface HistoryEntry {
  timestamp: number;
  input: any;
  output: any;
  decision: Decision;
  sequenceIndex: number;
}

export interface SessionMetrics {
  totalCalls: number;
  totalViolations: number;
  totalBlocked: number;
  totalRecovered: number;
  violationRate: number;
  blockRate: number;
  avgLatencyMs: number;
  totalTokens: number;
  totalCost: number;
  startTime: number;
  lastCallTime: number;
  driftScore: number;
}

// ── Decision ────────────────────────────────────────────────────────────────
export interface Decision {
  allowed: boolean;
  output?: any;
  violations: Violation[];
  latencyMs: number;
  recovered: boolean;
  recoveryAttempts: number;
  budgetSnapshot: BudgetSnapshot;
}

// ── Drift ───────────────────────────────────────────────────────────────────
export interface DriftConfig {
  windowSize: number;
  lambda: number;        // EWMA smoothing (0 < λ ≤ 1, lower = smoother)
  cusumSlack: number;    // CUSUM allowable slack (k)
  cusumThreshold: number; // CUSUM decision threshold (h)
  alertThreshold: number; // drift score to trigger alert (0-1)
}

export interface DriftResult {
  score: number;
  trending: 'stable' | 'drifting-up' | 'drifting-down';
  alert: boolean;
  ewma: { current: number; baseline: number; deviation: number };
  cusum: { upper: number; lower: number; signal: boolean };
  windowViolationRate: number;
  baselineViolationRate: number;
  sampleSize: number;
}

// ── Sequence ────────────────────────────────────────────────────────────────
export interface SequenceRule {
  name: string;
  description?: string;
  check: (history: HistoryEntry[]) => boolean;
  severity: Severity;
}

export interface SequenceConfig {
  maxLength?: number;
  rules: SequenceRule[];
}

// ── Testing ─────────────────────────────────────────────────────────────────
export type TestStrategy = 'boundary' | 'random' | 'adversarial' | 'sequence';

export interface TestConfig {
  iterations: number;
  strategies: TestStrategy[];
  timeoutMs?: number;
  seed?: number;
}

export interface TestResult {
  passed: boolean;
  totalTests: number;
  totalViolations: number;
  violations: TestViolation[];
  coverage: TestCoverage;
  durationMs: number;
  strategyCounts: Record<TestStrategy, { tests: number; violations: number }>;
}

export interface TestViolation {
  rule: string;
  input: any;
  output?: any;
  strategy: TestStrategy;
  iteration: number;
  phase: string;
}

export interface TestCoverage {
  rulesExercised: number;
  totalRules: number;
  percent: number;
  uncovered: string[];
}

// ── Audit ───────────────────────────────────────────────────────────────────
export interface AuditEntry {
  timestamp: number;
  sessionId: string;
  sequenceIndex: number;
  contractName: string;
  input: any;
  output?: any;
  decision: Decision;
}

export interface AuditReport {
  sessionId: string;
  contractName: string;
  startTime: number;
  endTime: number;
  totalActions: number;
  totalViolations: number;
  totalBlocked: number;
  complianceRate: number;
  budgetUsage: BudgetSnapshot;
  driftHistory: DriftResult[];
  violationsByRule: Record<string, number>;
  violationsBySeverity: Record<Severity, number>;
  timeline: AuditEntry[];
  summary: string;
}

// ── Harnessed Agent ─────────────────────────────────────────────────────────
export interface HarnessedAgent {
  call: (input: any, opts?: CallOptions) => Promise<Decision>;
  getMetrics: () => SessionMetrics;
  getDrift: () => DriftResult;
  getAudit: () => AuditReport;
  getBudget: () => BudgetSnapshot;
  getHistory: () => HistoryEntry[];
  setState: (key: string, value: any) => void;
  getState: () => SessionState;
  reset: () => void;
  readonly sessionId: string;
  readonly contract: Contract;
}

export interface CallOptions {
  tokensUsed?: number;
  costIncurred?: number;
  state?: Record<string, any>;
}
