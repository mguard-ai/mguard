#!/usr/bin/env node

import { Bulwark } from './index';
import { Contract, SequenceConfig, TestResult } from './types';
import * as fs from 'fs';
import * as path from 'path';

const HELP = `
bulwark — Production harness for AI agents

COMMANDS:
  init [name]         Scaffold a contract file
  test <file>         Run adversarial tests against a contract module
  validate <file>     Validate a contract definition
  info                Show library version and capabilities

OPTIONS:
  --iterations, -n    Number of test iterations (default: 100)
  --strategies, -s    Test strategies: boundary,random,adversarial,sequence
  --seed              Random seed for reproducible tests
  --json              Output results as JSON
  --help, -h          Show help

EXAMPLES:
  bulwark init my-agent
  bulwark test contracts/support.ts -n 200 -s boundary,adversarial
  bulwark validate contracts/trading.ts
`;

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(HELP);
    process.exit(0);
  }

  const command = args[0];

  try {
    switch (command) {
      case 'init': await init(args.slice(1)); break;
      case 'test': await test(args.slice(1)); break;
      case 'validate': await validate(args.slice(1)); break;
      case 'info': info(); break;
      default:
        console.error(`Unknown command: ${command}`);
        console.log(HELP);
        process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

// ── init ────────────────────────────────────────────────────────────────────

async function init(args: string[]) {
  const name = args[0] ?? 'my-agent';
  const filename = `${name}.contract.ts`;

  if (fs.existsSync(filename)) {
    console.error(`File already exists: ${filename}`);
    process.exit(1);
  }

  const template = `import { Bulwark } from 'bulwark';

// Define your agent's behavioral contract
export const contract = Bulwark.contract('${name}')
  .description('Behavioral contract for ${name}')

  // Preconditions — checked BEFORE the agent runs
  .pre('valid-input', (ctx) => {
    return ctx.input != null && ctx.input !== '';
  })

  // Postconditions — checked AFTER the agent runs
  .post('no-pii', (ctx) => {
    const output = String(ctx.output);
    // Block if output contains SSN-like patterns
    return !/\\b\\d{3}-\\d{2}-\\d{4}\\b/.test(output);
  })
  .post('reasonable-length', (ctx) => {
    return String(ctx.output).length <= 10000;
  })

  // Invariants — checked on every call
  .invariant('low-violation-rate', (ctx) => {
    return ctx.metrics.violationRate < 0.2;
  })

  // Budget — structural limits
  .budget({
    maxTokens: 100000,
    maxCost: 5.00,
    maxActions: 50,
  })

  // Recovery — what to do on violation
  .recover('retry', { maxRetries: 2 })

  .build();

// Export your agent function for testing
export async function agent(input: any): Promise<string> {
  // Replace this with your actual agent logic
  return \`Response to: \${input}\`;
}
`;

  fs.writeFileSync(filename, template);
  console.log(`Created ${filename}`);
  console.log(`\nNext steps:`);
  console.log(`  1. Edit ${filename} to define your agent's contract`);
  console.log(`  2. Run: bulwark test ${filename}`);
}

// ── test ────────────────────────────────────────────────────────────────────

async function test(args: string[]) {
  const file = args[0];
  if (!file) {
    console.error('Usage: bulwark test <file>');
    process.exit(1);
  }

  const iterations = getIntFlag(args, '--iterations', '-n') ?? 100;
  const strategiesStr = getFlag(args, '--strategies', '-s') ?? 'boundary,random,adversarial';
  const seed = getIntFlag(args, '--seed');
  const jsonOutput = args.includes('--json');

  const strategies = strategiesStr.split(',').map(s => s.trim()) as any[];

  // Load the contract module
  const absPath = path.resolve(file);
  let mod: any;
  try {
    mod = require(absPath);
  } catch {
    // Try tsx/ts-node import
    try {
      mod = await import(absPath);
    } catch (e) {
      console.error(`Cannot load module: ${absPath}`);
      console.error(`Make sure to compile TypeScript first or use: npx tsx bulwark test ${file}`);
      process.exit(1);
    }
  }

  const contract = mod.contract ?? mod.default?.contract;
  const agent = mod.agent ?? mod.default?.agent;

  if (!contract) {
    console.error(`Module must export 'contract'. Found exports: ${Object.keys(mod).join(', ')}`);
    process.exit(1);
  }
  if (!agent) {
    console.error(`Module must export 'agent'. Found exports: ${Object.keys(mod).join(', ')}`);
    process.exit(1);
  }

  console.log(`Testing contract: ${contract.name}`);
  console.log(`Strategies: ${strategies.join(', ')}`);
  console.log(`Iterations: ${iterations}`);
  if (seed !== undefined) console.log(`Seed: ${seed}`);
  console.log('');

  const result = await Bulwark.test(contract, agent, {
    iterations,
    strategies,
    seed,
  });

  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printTestResult(result);
  }

  process.exit(result.passed ? 0 : 1);
}

function printTestResult(r: TestResult) {
  console.log(`${r.passed ? 'PASSED' : 'FAILED'}`);
  console.log(`  Tests: ${r.totalTests}`);
  console.log(`  Violations: ${r.totalViolations}`);
  console.log(`  Duration: ${r.durationMs}ms`);
  console.log('');

  console.log('Strategy breakdown:');
  for (const [strategy, counts] of Object.entries(r.strategyCounts)) {
    if (counts.tests > 0) {
      console.log(`  ${strategy}: ${counts.tests} tests, ${counts.violations} violations`);
    }
  }
  console.log('');

  console.log(`Coverage: ${r.coverage.percent.toFixed(1)}% (${r.coverage.rulesExercised}/${r.coverage.totalRules} rules)`);
  if (r.coverage.uncovered.length > 0) {
    console.log(`  Uncovered: ${r.coverage.uncovered.join(', ')}`);
  }

  if (r.violations.length > 0) {
    console.log('');
    console.log('Violations found:');
    const grouped = new Map<string, number>();
    for (const v of r.violations) {
      grouped.set(v.rule, (grouped.get(v.rule) ?? 0) + 1);
    }
    for (const [rule, count] of [...grouped.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)) {
      console.log(`  ${rule}: ${count}x`);
    }
  }
}

// ── validate ────────────────────────────────────────────────────────────────

async function validate(args: string[]) {
  const file = args[0];
  if (!file) {
    console.error('Usage: bulwark validate <file>');
    process.exit(1);
  }

  const absPath = path.resolve(file);
  let mod: any;
  try {
    mod = require(absPath);
  } catch {
    try {
      mod = await import(absPath);
    } catch {
      console.error(`Cannot load module: ${absPath}`);
      process.exit(1);
    }
  }

  const contract: Contract = mod.contract ?? mod.default?.contract;
  if (!contract) {
    console.error(`Module must export 'contract'.`);
    process.exit(1);
  }

  console.log(`Contract: ${contract.name}`);
  console.log(`  Description: ${contract.description ?? '(none)'}`);
  console.log(`  Preconditions: ${contract.preconditions.length}`);
  console.log(`  Postconditions: ${contract.postconditions.length}`);
  console.log(`  Invariants: ${contract.invariants.length}`);

  if (contract.budget) {
    console.log('  Budget:');
    if (contract.budget.maxTokens) console.log(`    Max tokens: ${contract.budget.maxTokens}`);
    if (contract.budget.maxCost) console.log(`    Max cost: $${contract.budget.maxCost}`);
    if (contract.budget.maxActions) console.log(`    Max actions: ${contract.budget.maxActions}`);
    if (contract.budget.maxLatencyMs) console.log(`    Max latency: ${contract.budget.maxLatencyMs}ms`);
  }

  if (contract.recovery) {
    console.log(`  Recovery: ${contract.recovery.strategy}`);
  }

  const totalRules = contract.preconditions.length + contract.postconditions.length + contract.invariants.length;
  console.log(`\nValid contract with ${totalRules} rules.`);
}

// ── info ────────────────────────────────────────────────────────────────────

function info() {
  console.log('bulwark v1.0.0');
  console.log('Production harness for AI agents');
  console.log('');
  console.log('Capabilities:');
  console.log('  - Behavioral contracts (pre/post/invariant)');
  console.log('  - Budget enforcement (tokens, cost, actions, latency, duration)');
  console.log('  - Drift detection (EWMA + CUSUM)');
  console.log('  - Multi-step sequence safety');
  console.log('  - Adversarial contract testing');
  console.log('  - Compliance audit reports');
  console.log('  - Framework adapters (OpenAI, Anthropic, Vercel AI, LangChain)');
  console.log('');
  console.log('https://github.com/CGS22/bulwark');
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function getFlag(args: string[], long: string, short?: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === long || (short && args[i] === short)) {
      return args[i + 1];
    }
  }
  return undefined;
}

function getIntFlag(args: string[], long: string, short?: string): number | undefined {
  const val = getFlag(args, long, short);
  return val !== undefined ? parseInt(val, 10) : undefined;
}

main();
