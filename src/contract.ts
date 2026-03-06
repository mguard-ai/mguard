import {
  Contract, Rule, RuleCheck, Severity, BudgetConfig,
  RecoveryConfig, InputSchema, SequenceRule, SequenceConfig,
} from './types';

export class ContractBuilder {
  private _name: string;
  private _description?: string;
  private _preconditions: Rule[] = [];
  private _postconditions: Rule[] = [];
  private _invariants: Rule[] = [];
  private _budget?: BudgetConfig;
  private _recovery?: RecoveryConfig;
  private _inputSchema?: InputSchema;
  private _sequenceRules: SequenceRule[] = [];
  private _maxSequenceLength?: number;

  constructor(name: string) {
    this._name = name;
  }

  description(desc: string): this {
    this._description = desc;
    return this;
  }

  pre(name: string, check: RuleCheck, severity: Severity = 'critical', description?: string): this {
    this._preconditions.push({ name, check, severity, description });
    return this;
  }

  post(name: string, check: RuleCheck, severity: Severity = 'critical', description?: string): this {
    this._postconditions.push({ name, check, severity, description });
    return this;
  }

  invariant(name: string, check: RuleCheck, severity: Severity = 'critical', description?: string): this {
    this._invariants.push({ name, check, severity, description });
    return this;
  }

  budget(config: BudgetConfig): this {
    this._budget = config;
    return this;
  }

  recover(strategy: RecoveryConfig['strategy'], opts?: Partial<Omit<RecoveryConfig, 'strategy'>>): this {
    this._recovery = { strategy, ...opts };
    return this;
  }

  input(schema: InputSchema): this {
    this._inputSchema = schema;
    return this;
  }

  sequence(name: string, check: (history: any[]) => boolean, severity: Severity = 'critical', description?: string): this {
    this._sequenceRules.push({ name, check, severity, description });
    return this;
  }

  maxSteps(n: number): this {
    this._maxSequenceLength = n;
    return this;
  }

  build(): Contract & { sequenceConfig?: SequenceConfig } {
    if (!this._name) throw new Error('Contract must have a name');
    const contract: Contract & { sequenceConfig?: SequenceConfig } = {
      name: this._name,
      description: this._description,
      preconditions: [...this._preconditions],
      postconditions: [...this._postconditions],
      invariants: [...this._invariants],
      budget: this._budget ? { ...this._budget } : undefined,
      recovery: this._recovery ? { ...this._recovery } : undefined,
      inputSchema: this._inputSchema,
    };
    if (this._sequenceRules.length > 0 || this._maxSequenceLength) {
      contract.sequenceConfig = {
        rules: [...this._sequenceRules],
        maxLength: this._maxSequenceLength,
      };
    }
    return contract;
  }
}

// ── Contract composition ────────────────────────────────────────────────────

export function mergeContracts(name: string, ...contracts: Contract[]): Contract {
  const merged: Contract = {
    name,
    description: contracts.map(c => c.description).filter(Boolean).join(' + '),
    preconditions: [],
    postconditions: [],
    invariants: [],
  };

  const seenRules = new Set<string>();

  for (const c of contracts) {
    for (const rule of c.preconditions) {
      if (!seenRules.has(`pre:${rule.name}`)) {
        seenRules.add(`pre:${rule.name}`);
        merged.preconditions.push(rule);
      }
    }
    for (const rule of c.postconditions) {
      if (!seenRules.has(`post:${rule.name}`)) {
        seenRules.add(`post:${rule.name}`);
        merged.postconditions.push(rule);
      }
    }
    for (const rule of c.invariants) {
      if (!seenRules.has(`inv:${rule.name}`)) {
        seenRules.add(`inv:${rule.name}`);
        merged.invariants.push(rule);
      }
    }
  }

  // Strictest budget wins (lowest limits)
  const budgets = contracts.map(c => c.budget).filter(Boolean) as BudgetConfig[];
  if (budgets.length > 0) {
    merged.budget = {
      maxTokens: minDefined(...budgets.map(b => b.maxTokens)),
      maxCost: minDefined(...budgets.map(b => b.maxCost)),
      maxLatencyMs: minDefined(...budgets.map(b => b.maxLatencyMs)),
      maxActions: minDefined(...budgets.map(b => b.maxActions)),
      maxDurationMs: minDefined(...budgets.map(b => b.maxDurationMs)),
      degradation: budgets.find(b => b.degradation)?.degradation,
    };
  }

  // Most conservative recovery wins
  const recoveries = contracts.map(c => c.recovery).filter(Boolean) as RecoveryConfig[];
  if (recoveries.length > 0) {
    const priority: Record<string, number> = { block: 0, retry: 1, fallback: 2 };
    recoveries.sort((a, b) => (priority[a.strategy] ?? 9) - (priority[b.strategy] ?? 9));
    merged.recovery = { ...recoveries[0] };
  }

  return merged;
}

function minDefined(...values: (number | undefined)[]): number | undefined {
  const defined = values.filter((v): v is number => v !== undefined);
  return defined.length > 0 ? Math.min(...defined) : undefined;
}
