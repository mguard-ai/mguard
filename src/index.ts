import {
  AgentFn, Contract, HarnessedAgent, TestConfig, TestResult,
  DriftConfig, SequenceConfig, BudgetConfig, RecoveryConfig,
  SequenceRule,
} from './types';
import { ContractBuilder, mergeContracts } from './contract';
import { createHarnessedAgent } from './enforcer';
import { testContract } from './testing';
import { noRepeatLoop, noEscalation, maxCumulativeCost, noOscillation } from './sequence';

// ── Main API ────────────────────────────────────────────────────────────────

export class Bulwark {
  /**
   * Create a contract using the fluent builder.
   *
   *   const contract = Bulwark.contract('my-agent')
   *     .pre('valid-input', ctx => ctx.input != null)
   *     .post('no-pii', ctx => !hasPII(ctx.output))
   *     .budget({ maxTokens: 50000, maxCost: 1.00 })
   *     .recover('retry', { maxRetries: 3 })
   *     .build();
   */
  static contract(name: string): ContractBuilder {
    return new ContractBuilder(name);
  }

  /**
   * Wrap an agent function with a behavioral contract.
   * Returns a HarnessedAgent that enforces the contract on every call.
   *
   *   const safe = Bulwark.wrap(myAgent, contract);
   *   const result = await safe.call(input);
   *   if (result.allowed) {
   *     console.log(result.output);
   *   }
   */
  static wrap(
    agent: AgentFn,
    contract: Contract & { sequenceConfig?: SequenceConfig },
    driftConfig?: Partial<DriftConfig>,
  ): HarnessedAgent {
    return createHarnessedAgent(agent, contract, driftConfig);
  }

  /**
   * Run adversarial tests against a contract + agent pair.
   * Tests whether the agent stays within its contract under hostile conditions.
   *
   *   const results = await Bulwark.test(contract, myAgent, {
   *     iterations: 100,
   *     strategies: ['boundary', 'adversarial'],
   *   });
   *   console.log(results.passed, results.coverage);
   */
  static async test(
    contract: Contract & { sequenceConfig?: SequenceConfig },
    agent: AgentFn,
    config: TestConfig,
  ): Promise<TestResult> {
    return testContract(contract, agent, config);
  }

  /**
   * Merge multiple contracts into one. Strictest budget wins.
   * Rules are deduplicated by name, with first-seen taking precedence.
   *
   *   const merged = Bulwark.merge('combined',
   *     teamContract,
   *     complianceContract,
   *     costContract,
   *   );
   */
  static merge(name: string, ...contracts: Contract[]): Contract {
    return mergeContracts(name, ...contracts);
  }

  /**
   * Quick wrap — define contract inline.
   *
   *   const safe = Bulwark.guard(myAgent, {
   *     pre: { 'valid': ctx => ctx.input != null },
   *     post: { 'safe': ctx => isSafe(ctx.output) },
   *     budget: { maxCost: 1.00 },
   *   });
   */
  static guard(agent: AgentFn, opts: GuardOptions): HarnessedAgent {
    const builder = new ContractBuilder(opts.name ?? 'guard');
    if (opts.pre) {
      for (const [name, check] of Object.entries(opts.pre)) {
        builder.pre(name, check);
      }
    }
    if (opts.post) {
      for (const [name, check] of Object.entries(opts.post)) {
        builder.post(name, check);
      }
    }
    if (opts.invariants) {
      for (const [name, check] of Object.entries(opts.invariants)) {
        builder.invariant(name, check);
      }
    }
    if (opts.budget) builder.budget(opts.budget);
    if (opts.recovery) builder.recover(opts.recovery.strategy, opts.recovery);
    if (opts.maxSteps) builder.maxSteps(opts.maxSteps);
    return createHarnessedAgent(agent, builder.build());
  }

  // ── Built-in sequence rules ─────────────────────────────────────────────
  static sequences = {
    noRepeatLoop,
    noEscalation,
    maxCumulativeCost,
    noOscillation,
  };
}

export interface GuardOptions {
  name?: string;
  pre?: Record<string, (ctx: any) => boolean | Promise<boolean>>;
  post?: Record<string, (ctx: any) => boolean | Promise<boolean>>;
  invariants?: Record<string, (ctx: any) => boolean | Promise<boolean>>;
  budget?: BudgetConfig;
  recovery?: RecoveryConfig;
  maxSteps?: number;
}

// ── Re-exports ──────────────────────────────────────────────────────────────
export { ContractBuilder, mergeContracts } from './contract';
export { createHarnessedAgent } from './enforcer';
export { BudgetEnforcer } from './budget';
export { DriftMonitor } from './monitor';
export { SequenceEnforcer, noRepeatLoop, noEscalation, maxCumulativeCost, noOscillation } from './sequence';
export { testContract } from './testing';
export { Auditor } from './audit';
export { HashChain, AttestationEngine } from './attestation';
export { ImmuneSystem } from './immunity';
export * as witness from './witness/index';
export * as memory from './memory/index';
export * as adapters from './adapters/index';
export { openai } from './adapters/openai';
export { anthropic } from './adapters/anthropic';
export { vercelAI } from './adapters/vercel-ai';
export { langchain } from './adapters/langchain';
export * from './types';
