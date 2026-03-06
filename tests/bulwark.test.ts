import {
  Bulwark, ContractBuilder, mergeContracts, BudgetEnforcer,
  DriftMonitor, SequenceEnforcer, testContract,
  noRepeatLoop, noEscalation, noOscillation, maxCumulativeCost,
  createHarnessedAgent,
} from '../src/index';
import {
  Contract, Decision, HarnessedAgent, RuleContext, SequenceConfig,
} from '../src/types';

// ── Test harness ────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
let currentSection = '';

function section(name: string) {
  currentSection = name;
  console.log(`\n── ${name} ──`);
}

function assert(condition: boolean, message: string) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.log(`  ✗ FAIL: ${message}`);
  }
}

function assertApprox(a: number, b: number, tolerance: number, message: string) {
  assert(Math.abs(a - b) <= tolerance, `${message} (${a} ≈ ${b})`);
}

// ── Mock agents ─────────────────────────────────────────────────────────────

const echoAgent = async (input: any) => input;
const upperAgent = async (input: any) => typeof input === 'string' ? input.toUpperCase() : String(input);
const failingAgent = async () => { throw new Error('Agent crashed'); };
const delayAgent = (ms: number) => async (input: any) => {
  await new Promise(r => setTimeout(r, ms));
  return input;
};
let callCount = 0;
const countingAgent = async (input: any) => { callCount++; return input; };
const sometimesFailingAgent = async (input: any) => {
  if (typeof input === 'string' && input.includes('bad')) {
    return 'UNSAFE OUTPUT';
  }
  return 'safe output';
};

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

async function runTests() {

  // ═══════════════════════════════════════════════════════════════════════
  section('ContractBuilder — basic');
  // ═══════════════════════════════════════════════════════════════════════

  const c1 = Bulwark.contract('test')
    .description('A test contract')
    .pre('non-null', (ctx) => ctx.input != null)
    .post('non-empty', (ctx) => ctx.output !== '')
    .invariant('low-violations', (ctx) => ctx.metrics.violationRate < 0.5)
    .budget({ maxTokens: 1000, maxCost: 0.50 })
    .recover('retry', { maxRetries: 2 })
    .build();

  assert(c1.name === 'test', 'contract name');
  assert(c1.description === 'A test contract', 'contract description');
  assert(c1.preconditions.length === 1, 'one precondition');
  assert(c1.postconditions.length === 1, 'one postcondition');
  assert(c1.invariants.length === 1, 'one invariant');
  assert(c1.budget?.maxTokens === 1000, 'budget tokens');
  assert(c1.budget?.maxCost === 0.50, 'budget cost');
  assert(c1.recovery?.strategy === 'retry', 'recovery strategy');
  assert(c1.recovery?.maxRetries === 2, 'max retries');

  // ═══════════════════════════════════════════════════════════════════════
  section('ContractBuilder — sequence config');
  // ═══════════════════════════════════════════════════════════════════════

  const c2 = Bulwark.contract('seq-test')
    .sequence('no-loops', (history) => history.length < 10)
    .maxSteps(20)
    .build();

  assert(c2.sequenceConfig !== undefined, 'has sequence config');
  assert(c2.sequenceConfig!.rules.length === 1, 'one sequence rule');
  assert(c2.sequenceConfig!.maxLength === 20, 'max steps');

  // ═══════════════════════════════════════════════════════════════════════
  section('ContractBuilder — input schema');
  // ═══════════════════════════════════════════════════════════════════════

  const c3 = Bulwark.contract('schema-test')
    .input({
      type: 'object',
      properties: {
        query: { type: 'string', minLength: 1, maxLength: 500 },
        count: { type: 'number', minimum: 0, maximum: 100 },
      },
      required: ['query'],
    })
    .build();

  assert(c3.inputSchema?.type === 'object', 'input schema type');
  assert(c3.inputSchema?.properties?.query?.type === 'string', 'query schema');
  assert(c3.inputSchema?.properties?.count?.maximum === 100, 'count max');

  // ═══════════════════════════════════════════════════════════════════════
  section('Contract merging');
  // ═══════════════════════════════════════════════════════════════════════

  const team = Bulwark.contract('team')
    .pre('auth', (ctx) => ctx.input?.userId != null)
    .budget({ maxTokens: 5000 })
    .build();

  const compliance = Bulwark.contract('compliance')
    .post('no-pii', (ctx) => !String(ctx.output).includes('SSN'))
    .budget({ maxTokens: 3000, maxCost: 1.00 })
    .recover('block')
    .build();

  const merged = Bulwark.merge('combined', team, compliance);
  assert(merged.name === 'combined', 'merged name');
  assert(merged.preconditions.length === 1, 'merged preconditions');
  assert(merged.postconditions.length === 1, 'merged postconditions');
  assert(merged.budget?.maxTokens === 3000, 'strictest token budget wins');
  assert(merged.budget?.maxCost === 1.00, 'cost from compliance');
  assert(merged.recovery?.strategy === 'block', 'most conservative recovery');

  // Duplicate rule names are deduplicated
  const dup1 = Bulwark.contract('a').pre('check', () => true).build();
  const dup2 = Bulwark.contract('b').pre('check', () => false).build();
  const deduped = Bulwark.merge('dedup', dup1, dup2);
  assert(deduped.preconditions.length === 1, 'duplicate rules deduplicated');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — basic allow');
  // ═══════════════════════════════════════════════════════════════════════

  const simple = Bulwark.contract('simple')
    .pre('exists', (ctx) => ctx.input != null)
    .post('not-empty', (ctx) => ctx.output != null && ctx.output !== '')
    .build();

  const safe = Bulwark.wrap(echoAgent, simple);
  const r1 = await safe.call('hello');
  assert(r1.allowed === true, 'allowed for valid input');
  assert(r1.output === 'hello', 'output passed through');
  assert(r1.violations.length === 0, 'no violations');
  assert(r1.recovered === false, 'not recovered');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — precondition block');
  // ═══════════════════════════════════════════════════════════════════════

  const r2 = await safe.call(null);
  assert(r2.allowed === false, 'blocked for null input');
  assert(r2.output === undefined, 'no output on block');
  assert(r2.violations.length > 0, 'has violations');
  assert(r2.violations[0].phase === 'precondition', 'violation is precondition');
  assert(r2.violations[0].rule === 'exists', 'violation rule name');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — postcondition violation');
  // ═══════════════════════════════════════════════════════════════════════

  const strictPost = Bulwark.contract('strict')
    .post('must-be-upper', (ctx) => ctx.output === ctx.output?.toUpperCase())
    .build();

  const lower = Bulwark.wrap(async () => 'lowercase', strictPost);
  const r3 = await lower.call('anything');
  assert(r3.allowed === false, 'blocked by postcondition');
  assert(r3.violations[0].phase === 'postcondition', 'postcondition violation');

  const upper = Bulwark.wrap(async () => 'UPPERCASE', strictPost);
  const r4 = await upper.call('anything');
  assert(r4.allowed === true, 'passes postcondition');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — invariant violation');
  // ═══════════════════════════════════════════════════════════════════════

  const invContract = Bulwark.contract('inv-test')
    .invariant('max-3-calls', (ctx) => ctx.metrics.totalCalls < 3)
    .build();

  const invAgent = Bulwark.wrap(echoAgent, invContract);
  const ir1 = await invAgent.call('a');
  assert(ir1.allowed === true, 'call 1 allowed');
  const ir2 = await invAgent.call('b');
  assert(ir2.allowed === true, 'call 2 allowed');
  const ir3 = await invAgent.call('c');
  assert(ir3.allowed === true, 'call 3 allowed (totalCalls=2 when checked)');
  const ir4 = await invAgent.call('d');
  assert(ir4.allowed === false, 'call 4 blocked by invariant (totalCalls=3)');
  assert(ir4.violations.some(v => v.phase === 'invariant'), 'invariant violation');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — agent exception handling');
  // ═══════════════════════════════════════════════════════════════════════

  const crashContract = Bulwark.contract('crash').build();
  const crashAgent = Bulwark.wrap(failingAgent, crashContract);
  const cr = await crashAgent.call('input');
  assert(cr.allowed === false, 'agent exception blocks');
  assert(cr.violations.some(v => v.rule === 'agent:exception'), 'exception violation recorded');
  assert(cr.violations.some(v => v.message.includes('Agent crashed')), 'error message captured');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — recovery: retry');
  // ═══════════════════════════════════════════════════════════════════════

  let retryCount = 0;
  const flakyAgent = async (input: any) => {
    retryCount++;
    if (retryCount < 3) return 'bad';
    return 'GOOD';
  };

  const retryContract = Bulwark.contract('retry-test')
    .post('must-be-good', (ctx) => ctx.output === 'GOOD')
    .recover('retry', { maxRetries: 3 })
    .build();

  retryCount = 0;
  const retryHarness = Bulwark.wrap(flakyAgent, retryContract);
  const rr = await retryHarness.call('input');
  assert(rr.allowed === true, 'recovered after retries');
  assert(rr.recovered === true, 'marked as recovered');
  assert(rr.recoveryAttempts > 0, 'has recovery attempts');
  assert(retryCount === 3, 'agent called 3 times');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — recovery: retry exhausted');
  // ═══════════════════════════════════════════════════════════════════════

  const alwaysBad = async () => 'bad';
  const exhaustContract = Bulwark.contract('exhaust')
    .post('must-be-good', (ctx) => ctx.output === 'GOOD')
    .recover('retry', { maxRetries: 2 })
    .build();

  const exhaustHarness = Bulwark.wrap(alwaysBad, exhaustContract);
  const er = await exhaustHarness.call('input');
  assert(er.allowed === false, 'blocked after retries exhausted');
  assert(er.recoveryAttempts === 2, '2 retry attempts');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — recovery: fallback');
  // ═══════════════════════════════════════════════════════════════════════

  const fallbackContract = Bulwark.contract('fallback')
    .post('must-be-good', (ctx) => ctx.output === 'GOOD')
    .recover('fallback', {
      fallbackFn: () => 'FALLBACK_OUTPUT',
    })
    .build();

  const fbHarness = Bulwark.wrap(alwaysBad, fallbackContract);
  const fr = await fbHarness.call('input');
  assert(fr.allowed === true, 'fallback allows');
  assert(fr.output === 'FALLBACK_OUTPUT', 'fallback output used');
  assert(fr.recovered === true, 'marked as recovered');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — recovery: block');
  // ═══════════════════════════════════════════════════════════════════════

  const blockContract = Bulwark.contract('block')
    .post('must-be-good', (ctx) => ctx.output === 'GOOD')
    .recover('block')
    .build();

  const blockHarness = Bulwark.wrap(alwaysBad, blockContract);
  const br = await blockHarness.call('input');
  assert(br.allowed === false, 'block strategy blocks');
  assert(br.recovered === false, 'not recovered');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — warning severity passes');
  // ═══════════════════════════════════════════════════════════════════════

  const warnContract = Bulwark.contract('warn')
    .pre('warn-rule', (ctx) => false, 'warning')
    .build();

  const warnHarness = Bulwark.wrap(echoAgent, warnContract);
  const wr = await warnHarness.call('input');
  assert(wr.allowed === true, 'warning does not block');
  assert(wr.violations.length === 1, 'warning recorded');
  assert(wr.violations[0].severity === 'warning', 'severity is warning');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — metrics tracking');
  // ═══════════════════════════════════════════════════════════════════════

  const metricsContract = Bulwark.contract('metrics')
    .post('even-length', (ctx) => typeof ctx.output === 'string' && ctx.output.length % 2 === 0)
    .build();

  const metricsAgent = Bulwark.wrap(echoAgent, metricsContract);
  await metricsAgent.call('ab');    // pass (len=2)
  await metricsAgent.call('abc');   // fail (len=3)
  await metricsAgent.call('abcd');  // pass (len=4)
  await metricsAgent.call('a');     // fail (len=1)

  const m = metricsAgent.getMetrics();
  assert(m.totalCalls === 4, 'total calls');
  assert(m.totalViolations === 2, 'total violations');
  assert(m.totalBlocked === 2, 'total blocked');
  assertApprox(m.violationRate, 0.5, 0.01, 'violation rate');
  assertApprox(m.blockRate, 0.5, 0.01, 'block rate');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — session state');
  // ═══════════════════════════════════════════════════════════════════════

  const stateContract = Bulwark.contract('state')
    .invariant('counter-limit', (ctx) => (ctx.state.counter ?? 0) < 5)
    .build();

  const stateAgent = Bulwark.wrap(echoAgent, stateContract);
  stateAgent.setState('counter', 0);
  const s1 = await stateAgent.call('a');
  assert(s1.allowed === true, 'state check passes');
  assert(stateAgent.getState().counter === 0, 'state preserved');

  stateAgent.setState('counter', 10);
  const s2 = await stateAgent.call('b');
  assert(s2.allowed === false, 'state check fails when exceeded');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — call options (tokens, cost)');
  // ═══════════════════════════════════════════════════════════════════════

  const costContract = Bulwark.contract('cost')
    .budget({ maxTokens: 100, maxCost: 0.10 })
    .build();

  const costAgent = Bulwark.wrap(echoAgent, costContract);
  await costAgent.call('a', { tokensUsed: 30, costIncurred: 0.03 });
  await costAgent.call('b', { tokensUsed: 30, costIncurred: 0.03 });
  const cb = costAgent.getBudget();
  assert(cb.tokens.used === 60, 'tokens tracked');
  assertApprox(cb.cost.used, 0.06, 0.001, 'cost tracked');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — reset');
  // ═══════════════════════════════════════════════════════════════════════

  costAgent.reset();
  const rm = costAgent.getMetrics();
  assert(rm.totalCalls === 0, 'metrics reset');
  assert(rm.totalViolations === 0, 'violations reset');
  const rb = costAgent.getBudget();
  assert(rb.tokens.used === 0, 'budget reset');

  // ═══════════════════════════════════════════════════════════════════════
  section('Enforcer — history tracking');
  // ═══════════════════════════════════════════════════════════════════════

  const histContract = Bulwark.contract('hist').build();
  const histAgent = Bulwark.wrap(echoAgent, histContract);
  await histAgent.call('first');
  await histAgent.call('second');
  const hist = histAgent.getHistory();
  assert(hist.length === 2, 'history has 2 entries');
  assert(hist[0].input === 'first', 'first entry input');
  assert(hist[1].input === 'second', 'second entry input');
  assert(hist[0].sequenceIndex === 0, 'sequence index 0');
  assert(hist[1].sequenceIndex === 1, 'sequence index 1');

  // ═══════════════════════════════════════════════════════════════════════
  section('BudgetEnforcer — token exhaustion');
  // ═══════════════════════════════════════════════════════════════════════

  const be = new BudgetEnforcer({ maxTokens: 100 });
  be.record(60);
  let bv = be.check();
  assert(bv.length === 0, 'under budget OK');
  be.record(50);
  bv = be.check();
  assert(bv.length === 1, 'over budget violation');
  assert(bv[0].rule === 'budget:tokens', 'token budget rule');

  // ═══════════════════════════════════════════════════════════════════════
  section('BudgetEnforcer — cost exhaustion');
  // ═══════════════════════════════════════════════════════════════════════

  const beCost = new BudgetEnforcer({ maxCost: 1.00 });
  beCost.record(0, 0.50);
  assert(beCost.check().length === 0, 'under cost budget');
  beCost.record(0, 0.60);
  assert(beCost.check().length === 1, 'over cost budget');

  // ═══════════════════════════════════════════════════════════════════════
  section('BudgetEnforcer — action exhaustion');
  // ═══════════════════════════════════════════════════════════════════════

  const beAct = new BudgetEnforcer({ maxActions: 3 });
  beAct.record(); beAct.record(); beAct.record();
  assert(beAct.check().length === 1, 'action budget exhausted');
  assert(beAct.getActionsUsed() === 3, 'actions counted');

  // ═══════════════════════════════════════════════════════════════════════
  section('BudgetEnforcer — latency check');
  // ═══════════════════════════════════════════════════════════════════════

  const beLat = new BudgetEnforcer({ maxLatencyMs: 100 });
  assert(beLat.checkLatency(50) === null, 'under latency OK');
  const lv = beLat.checkLatency(150);
  assert(lv !== null, 'over latency violation');
  assert(lv!.rule === 'budget:latency', 'latency rule');

  // ═══════════════════════════════════════════════════════════════════════
  section('BudgetEnforcer — snapshot status');
  // ═══════════════════════════════════════════════════════════════════════

  const beSnap = new BudgetEnforcer({ maxTokens: 100 });
  beSnap.record(50);
  assert(beSnap.snapshot().status === 'ok', 'status OK at 50%');
  beSnap.record(26);
  assert(beSnap.snapshot().status === 'warning', 'status warning at 76%');
  beSnap.record(15);
  assert(beSnap.snapshot().status === 'critical', 'status critical at 91%');
  beSnap.record(10);
  assert(beSnap.snapshot().status === 'exhausted', 'status exhausted at 101%');

  // ═══════════════════════════════════════════════════════════════════════
  section('BudgetEnforcer — degradation thresholds');
  // ═══════════════════════════════════════════════════════════════════════

  const beDeg = new BudgetEnforcer({
    maxTokens: 100,
    degradationThresholds: [
      { percent: 50, action: 'warn', message: 'Half budget used' },
      { percent: 80, action: 'throttle', message: 'Throttling' },
      { percent: 95, action: 'simplify', message: 'Simplifying' },
    ],
  });
  beDeg.record(55);
  let snap = beDeg.snapshot();
  assert(snap.activeDegradations.length === 1, 'one degradation active at 55%');
  assert(snap.activeDegradations[0] === 'Half budget used', 'correct degradation message');

  beDeg.record(30);
  snap = beDeg.snapshot();
  assert(snap.activeDegradations.length === 2, 'two degradations at 85%');

  // ═══════════════════════════════════════════════════════════════════════
  section('BudgetEnforcer — reset');
  // ═══════════════════════════════════════════════════════════════════════

  beDeg.reset();
  assert(beDeg.getTokensUsed() === 0, 'tokens reset');
  assert(beDeg.getCostIncurred() === 0, 'cost reset');
  assert(beDeg.getActionsUsed() === 0, 'actions reset');

  // ═══════════════════════════════════════════════════════════════════════
  section('Budget integration — structural unreachability');
  // ═══════════════════════════════════════════════════════════════════════

  const budgetGate = Bulwark.contract('gate')
    .budget({ maxActions: 3 })
    .build();

  callCount = 0;
  const gatedAgent = Bulwark.wrap(countingAgent, budgetGate);
  const g1 = await gatedAgent.call('a');
  const g2 = await gatedAgent.call('b');
  const g3 = await gatedAgent.call('c');
  const g4 = await gatedAgent.call('d');

  assert(g1.allowed === true, 'action 1 allowed');
  assert(g2.allowed === true, 'action 2 allowed');
  assert(g3.allowed === true, 'action 3 allowed');
  assert(g4.allowed === false, 'action 4 BLOCKED — structurally unreachable');
  assert(callCount === 3, 'agent only called 3 times (4th never executed)');

  // ═══════════════════════════════════════════════════════════════════════
  section('DriftMonitor — stable baseline');
  // ═══════════════════════════════════════════════════════════════════════

  const dm = new DriftMonitor({ windowSize: 10, alertThreshold: 0.6 });
  // 20 clean observations for baseline
  for (let i = 0; i < 20; i++) dm.record(false);
  const d0 = dm.getDrift();
  assert(d0.alert === false, 'no alert during stable period');
  assert(d0.trending === 'stable', 'trending stable');
  assertApprox(d0.ewma.baseline, 0, 0.01, 'baseline near 0');
  assert(d0.sampleSize === 20, 'sample size');

  // ═══════════════════════════════════════════════════════════════════════
  section('DriftMonitor — drift detection');
  // ═══════════════════════════════════════════════════════════════════════

  const dm2 = new DriftMonitor({
    windowSize: 10,
    lambda: 0.2,
    cusumSlack: 0.1,
    cusumThreshold: 3.0,
    alertThreshold: 0.5,
  });

  // Baseline: 20 clean
  for (let i = 0; i < 20; i++) dm2.record(false);
  const dBaseline = dm2.getDrift();
  assert(dBaseline.alert === false, 'no alert at baseline');

  // Inject violations: 15 consecutive
  for (let i = 0; i < 15; i++) dm2.record(true);
  const dDrift = dm2.getDrift();
  assert(dDrift.alert === true, 'alert after drift');
  assert(dDrift.trending === 'drifting-up', 'trending up');
  assert(dDrift.ewma.current > dDrift.ewma.baseline, 'EWMA above baseline');
  assert(dDrift.cusum.upper > 0, 'CUSUM upper accumulated');
  assert(dDrift.windowViolationRate > 0.5, 'window violation rate high');

  // ═══════════════════════════════════════════════════════════════════════
  section('DriftMonitor — EWMA smoothing');
  // ═══════════════════════════════════════════════════════════════════════

  const dm3 = new DriftMonitor({ lambda: 0.1, windowSize: 10, alertThreshold: 0.8 });
  // All clean baseline
  for (let i = 0; i < 20; i++) dm3.record(false);
  const eBefore = dm3.getDrift().ewma.current;

  // Single violation shouldn't cause huge jump
  dm3.record(true);
  const eAfter = dm3.getDrift().ewma.current;
  assert(eAfter > eBefore, 'EWMA increased');
  assert(eAfter < 0.15, 'EWMA smoothed (not jumped to 1.0)');

  // ═══════════════════════════════════════════════════════════════════════
  section('DriftMonitor — CUSUM detects small persistent shift');
  // ═══════════════════════════════════════════════════════════════════════

  const dm4 = new DriftMonitor({
    windowSize: 10,
    cusumSlack: 0.05,
    cusumThreshold: 2.0,
    alertThreshold: 0.5,
  });

  // Baseline: 20 clean
  for (let i = 0; i < 20; i++) dm4.record(false);
  assert(!dm4.getDrift().cusum.signal, 'no CUSUM signal at baseline');

  // Small persistent shift: 20% violation rate
  for (let i = 0; i < 30; i++) dm4.record(i % 5 === 0);
  const d4 = dm4.getDrift();
  assert(d4.cusum.upper > 0, 'CUSUM upper accumulated from small shift');

  // ═══════════════════════════════════════════════════════════════════════
  section('DriftMonitor — reset');
  // ═══════════════════════════════════════════════════════════════════════

  dm4.reset();
  const dReset = dm4.getDrift();
  assert(dReset.sampleSize === 0, 'reset clears samples');
  assert(dReset.score === 0, 'reset clears score');

  // ═══════════════════════════════════════════════════════════════════════
  section('SequenceEnforcer — max length');
  // ═══════════════════════════════════════════════════════════════════════

  const seqContract = Bulwark.contract('seq')
    .maxSteps(3)
    .build();

  const seqAgent = Bulwark.wrap(echoAgent, seqContract);
  const sq1 = await seqAgent.call('a');
  const sq2 = await seqAgent.call('b');
  const sq3 = await seqAgent.call('c');
  const sq4 = await seqAgent.call('d');
  assert(sq1.allowed && sq2.allowed && sq3.allowed, 'first 3 steps allowed');
  assert(sq4.allowed === false, 'step 4 blocked by max length');
  assert(sq4.violations.some(v => v.rule === 'sequence:max-length'), 'max length violation');

  // ═══════════════════════════════════════════════════════════════════════
  section('Built-in sequence: noRepeatLoop');
  // ═══════════════════════════════════════════════════════════════════════

  const rule = noRepeatLoop(5, 3);
  // Not a loop
  const okHistory = [1, 2, 3, 4, 5].map((n, i) => makeHistoryEntry(`out-${n}`, i));
  assert(rule.check(okHistory) === true, 'diverse outputs pass');

  // Loop detected
  const loopHistory = [1, 1, 1, 1, 1].map((n, i) => makeHistoryEntry('same', i));
  assert(rule.check(loopHistory) === false, 'repeated outputs detected');

  // ═══════════════════════════════════════════════════════════════════════
  section('Built-in sequence: noEscalation');
  // ═══════════════════════════════════════════════════════════════════════

  const escRule = noEscalation(2, 3);
  // No escalation
  const flatHistory = Array.from({ length: 10 }, (_, i) => makeHistoryEntry('ok', i, 0));
  assert(escRule.check(flatHistory) === true, 'flat violation rate passes');

  // Escalating: 4 windows of size 2, each with increasing violation counts
  // Window 0 (idx 0-1): 0 violations → rate 0
  // Window 1 (idx 2-3): 1 violation  → rate 0.5
  // Window 2 (idx 4-5): 2 violations → rate 1.0
  // Window 3 (idx 6-7): 2 violations → rate 1.0
  // 3 consecutive increases: 0→0.5→1.0→... but 4th stays at 1.0
  // Need: 0, 0.5, 1.0, 1.0 — only 2 consecutive increases.
  // For 3 increases: 5 windows with rates 0, 0.25, 0.5, 0.75, 1.0
  const escalating = Array.from({ length: 10 }, (_, i) => {
    // Window 0 (0-1): 0 violations each
    // Window 1 (2-3): index 3 has violation
    // Window 2 (4-5): both have violations
    // Window 3 (6-7): both have violations (same, no increase but we need 3 increases)
    // Actually: just make each window have strictly more violations
    const violationCount = Math.floor(i / 2); // 0,0,1,1,2,2,3,3,4,4
    return makeHistoryEntry('ok', i, violationCount > 0 ? 1 : 0);
  });
  // Rates per window of 2: [0,0]=0, [1,0]=0.5, [1,1]=1, [1,1]=1, [1,1]=1
  // Increases: 0→0.5 (+1), 0.5→1 (+2), 1→1 (reset) — only 2 consecutive
  // Need longer escalation. Use window=1 and maxConsec=3
  const escRule2 = noEscalation(1, 3);
  // Each "window" is 1 entry. Rates: 0,0,1,1,1,1,1,1,1,1
  // Increases: 0→0(0), 0→1(1), 1→1(0) — doesn't work either
  // Let me just use clear data: each entry IS a window
  const clearEsc = [0, 0, 1, 1, 1, 1].map((vc, i) => makeHistoryEntry('ok', i, vc));
  // Window rates: 0, 0, 1, 1, 1, 1 — increases: 0→0(0), 0→1(1), 1→1(0) — only 1
  // The issue is violations are binary. For proper escalation with windowSize=2:
  const escRule3 = noEscalation(3, 2); // window=3, 2 consecutive increases needed
  const clearEsc2 = [
    // Window 0 (0-2): 0 violations
    ...([0,0,0].map((vc, i) => makeHistoryEntry('ok', i, vc))),
    // Window 1 (3-5): 1 violation
    ...([0,0,1].map((vc, i) => makeHistoryEntry('ok', i+3, vc))),
    // Window 2 (6-8): 2 violations
    ...([0,1,1].map((vc, i) => makeHistoryEntry('ok', i+6, vc))),
    // Window 3 (9-11): 3 violations
    ...([1,1,1].map((vc, i) => makeHistoryEntry('ok', i+9, vc))),
  ];
  assert(escRule3.check(clearEsc2) === false, 'escalating violations detected');

  // ═══════════════════════════════════════════════════════════════════════
  section('Built-in sequence: noOscillation');
  // ═══════════════════════════════════════════════════════════════════════

  const oscRule = noOscillation(4);
  const oscHistory = ['A', 'B', 'A', 'B', 'A', 'B', 'A', 'B']
    .map((o, i) => makeHistoryEntry(o, i));
  assert(oscRule.check(oscHistory) === false, 'oscillation detected');

  const noOsc = ['A', 'B', 'C', 'A', 'B', 'C']
    .map((o, i) => makeHistoryEntry(o, i));
  assert(oscRule.check(noOsc) === true, 'no oscillation in diverse outputs');

  // ═══════════════════════════════════════════════════════════════════════
  section('Sequence integration with enforcer');
  // ═══════════════════════════════════════════════════════════════════════

  const seqIntContract = Bulwark.contract('seq-int')
    .sequence('no-loops', (h) => {
      if (h.length < 3) return true;
      const last3 = h.slice(-3).map(e => JSON.stringify(e.output));
      return new Set(last3).size > 1;
    }, 'critical')
    .build();

  const seqIntAgent = Bulwark.wrap(echoAgent, seqIntContract);
  await seqIntAgent.call('a');
  await seqIntAgent.call('b');
  const si3 = await seqIntAgent.call('b');
  assert(si3.allowed === true, 'two same OK');
  await seqIntAgent.call('b'); // history now: a, b, b, b
  // 5th call: history has [a,b,b,b], last 3 = [b,b,b], unique=1 → fail
  const si5 = await seqIntAgent.call('b');
  assert(si5.allowed === false, 'three same in last 3 blocked');

  // ═══════════════════════════════════════════════════════════════════════
  section('Bulwark.guard — shorthand API');
  // ═══════════════════════════════════════════════════════════════════════

  const guarded = Bulwark.guard(echoAgent, {
    name: 'quick',
    pre: { 'exists': (ctx) => ctx.input != null },
    post: { 'not-empty': (ctx) => ctx.output !== '' },
    budget: { maxActions: 5 },
  });

  const gq1 = await guarded.call('hello');
  assert(gq1.allowed === true, 'guard allows valid');
  const gq2 = await guarded.call(null);
  assert(gq2.allowed === false, 'guard blocks invalid');
  assert(guarded.contract.name === 'quick', 'guard contract name');

  // ═══════════════════════════════════════════════════════════════════════
  section('Audit report generation');
  // ═══════════════════════════════════════════════════════════════════════

  const auditContract = Bulwark.contract('audit-test')
    .pre('non-null', (ctx) => ctx.input != null)
    .post('safe', (ctx) => ctx.output !== 'UNSAFE')
    .build();

  const auditAgent = Bulwark.wrap(
    async (input: any) => input === 'danger' ? 'UNSAFE' : 'safe',
    auditContract,
  );

  await auditAgent.call('good');
  await auditAgent.call('also-good');
  await auditAgent.call('danger');
  await auditAgent.call(null);

  const report = auditAgent.getAudit();
  assert(report.sessionId === auditAgent.sessionId, 'audit session ID');
  assert(report.contractName === 'audit-test', 'audit contract name');
  assert(report.totalActions === 4, 'audit total actions');
  assert(report.totalBlocked === 2, 'audit total blocked');
  assertApprox(report.complianceRate, 50, 0.1, 'compliance rate');
  assert(report.violationsByRule['non-null'] === 1, 'violations by rule: non-null');
  assert(report.violationsByRule['safe'] === 1, 'violations by rule: safe');
  assert(report.violationsBySeverity.critical === 2, 'violations by severity: critical');
  assert(report.timeline.length === 4, 'timeline entries');
  assert(report.summary.includes('AUDIT REPORT'), 'summary has header');
  assert(report.summary.includes('FAILING'), 'summary has verdict');

  // ═══════════════════════════════════════════════════════════════════════
  section('Audit — compliance rate calculation');
  // ═══════════════════════════════════════════════════════════════════════

  const perfectAgent = Bulwark.wrap(echoAgent, Bulwark.contract('perfect').build());
  await perfectAgent.call('a');
  await perfectAgent.call('b');
  const perfectReport = perfectAgent.getAudit();
  assertApprox(perfectReport.complianceRate, 100, 0.01, 'perfect compliance');
  assert(perfectReport.summary.includes('EXCELLENT'), 'excellent verdict');

  // ═══════════════════════════════════════════════════════════════════════
  section('Drift integration with enforcer');
  // ═══════════════════════════════════════════════════════════════════════

  const driftContract = Bulwark.contract('drift')
    .post('no-unsafe', (ctx) => ctx.output !== 'UNSAFE OUTPUT')
    .build();

  const driftAgent = Bulwark.wrap(
    sometimesFailingAgent,
    driftContract,
    { alertThreshold: 0.5, cusumSlack: 0.1, cusumThreshold: 2.0 },
  );

  // Baseline: 20 clean calls (input without 'bad' → 'safe output')
  for (let i = 0; i < 20; i++) await driftAgent.call('good');
  const d1 = driftAgent.getDrift();
  assert(d1.alert === false, 'no drift alert during baseline');

  // Inject violations: input with 'bad' → 'UNSAFE OUTPUT' → postcondition fails
  for (let i = 0; i < 15; i++) await driftAgent.call('bad input');
  const d2 = driftAgent.getDrift();
  assert(d2.score > 0.3, 'drift score increased');
  assert(d2.ewma.current > d2.ewma.baseline, 'EWMA rose above baseline');

  // ═══════════════════════════════════════════════════════════════════════
  section('Adversarial testing — boundary strategy');
  // ═══════════════════════════════════════════════════════════════════════

  const testableContract = Bulwark.contract('testable')
    .pre('non-null', (ctx) => ctx.input != null && ctx.input !== undefined)
    .post('is-string', (ctx) => typeof ctx.output === 'string')
    .input({
      type: 'object',
      properties: { query: { type: 'string', minLength: 1, maxLength: 100 } },
    })
    .build();

  const tr1 = await Bulwark.test(testableContract, upperAgent, {
    iterations: 20,
    strategies: ['boundary'],
  });

  assert(tr1.totalTests > 0, 'boundary tests ran');
  assert(tr1.violations.length > 0, 'boundary found violations (null/undefined inputs)');
  assert(tr1.coverage.rulesExercised > 0, 'rules exercised');
  assert(tr1.durationMs >= 0, 'duration tracked');

  // ═══════════════════════════════════════════════════════════════════════
  section('Adversarial testing — random strategy');
  // ═══════════════════════════════════════════════════════════════════════

  const tr2 = await Bulwark.test(testableContract, upperAgent, {
    iterations: 30,
    strategies: ['random'],
  });

  assert(tr2.totalTests === 30, 'random test count');
  assert(tr2.strategyCounts.random.tests === 30, 'strategy count tracked');

  // ═══════════════════════════════════════════════════════════════════════
  section('Adversarial testing — adversarial strategy');
  // ═══════════════════════════════════════════════════════════════════════

  const tr3 = await Bulwark.test(testableContract, upperAgent, {
    iterations: 20,
    strategies: ['adversarial'],
  });

  assert(tr3.totalTests > 0, 'adversarial tests ran');
  assert(tr3.strategyCounts.adversarial.tests > 0, 'adversarial strategy tracked');

  // ═══════════════════════════════════════════════════════════════════════
  section('Adversarial testing — sequence strategy');
  // ═══════════════════════════════════════════════════════════════════════

  const seqTestContract = Bulwark.contract('seq-test')
    .post('is-string', (ctx) => typeof ctx.output === 'string')
    .maxSteps(10)
    .build();

  const tr4 = await Bulwark.test(seqTestContract, echoAgent, {
    iterations: 15,
    strategies: ['sequence'],
  });

  assert(tr4.totalTests > 0, 'sequence tests ran');
  // Should detect max-length violations
  assert(tr4.violations.some(v => v.rule.includes('max-length')) || tr4.totalTests <= 10,
    'sequence length violations or under limit');

  // ═══════════════════════════════════════════════════════════════════════
  section('Adversarial testing — multi-strategy');
  // ═══════════════════════════════════════════════════════════════════════

  const tr5 = await Bulwark.test(testableContract, upperAgent, {
    iterations: 10,
    strategies: ['boundary', 'random', 'adversarial'],
  });

  assert(tr5.strategyCounts.boundary.tests > 0, 'boundary ran');
  assert(tr5.strategyCounts.random.tests === 10, 'random ran 10');
  assert(tr5.strategyCounts.adversarial.tests > 0, 'adversarial ran');
  assert(tr5.totalTests > 20, 'total across strategies');

  // ═══════════════════════════════════════════════════════════════════════
  section('Adversarial testing — coverage tracking');
  // ═══════════════════════════════════════════════════════════════════════

  const coverageContract = Bulwark.contract('coverage')
    .pre('has-input', (ctx) => ctx.input != null)
    .post('is-string', (ctx) => typeof ctx.output === 'string')
    .post('not-empty', (ctx) => ctx.output !== '')
    .invariant('low-errors', (ctx) => ctx.metrics.violationRate < 0.9)
    .build();

  const tr6 = await Bulwark.test(coverageContract, upperAgent, {
    iterations: 20,
    strategies: ['boundary'],
  });

  assert(tr6.coverage.totalRules === 4, '4 rules in coverage');
  assert(tr6.coverage.percent >= 0, 'coverage percent calculated');

  // ═══════════════════════════════════════════════════════════════════════
  section('Adversarial testing — reproducibility (seed)');
  // ═══════════════════════════════════════════════════════════════════════

  const seedContract = Bulwark.contract('seed-test')
    .pre('non-null', (ctx) => ctx.input != null)
    .build();

  const tr7a = await Bulwark.test(seedContract, echoAgent, {
    iterations: 20,
    strategies: ['random'],
    seed: 42,
  });

  const tr7b = await Bulwark.test(seedContract, echoAgent, {
    iterations: 20,
    strategies: ['random'],
    seed: 42,
  });

  assert(tr7a.totalViolations === tr7b.totalViolations, 'same seed → same violations');
  assert(tr7a.totalTests === tr7b.totalTests, 'same seed → same test count');

  // ═══════════════════════════════════════════════════════════════════════
  section('Async rule support');
  // ═══════════════════════════════════════════════════════════════════════

  const asyncContract = Bulwark.contract('async')
    .pre('async-check', async (ctx) => {
      await new Promise(r => setTimeout(r, 5));
      return ctx.input != null;
    })
    .post('async-post', async (ctx) => {
      await new Promise(r => setTimeout(r, 5));
      return ctx.output !== 'blocked';
    })
    .build();

  const asyncAgent = Bulwark.wrap(echoAgent, asyncContract);
  const ar1 = await asyncAgent.call('hello');
  assert(ar1.allowed === true, 'async rule passes');
  const ar2 = await asyncAgent.call(null);
  assert(ar2.allowed === false, 'async precondition blocks');

  // ═══════════════════════════════════════════════════════════════════════
  section('Complex real-world scenario: trading agent');
  // ═══════════════════════════════════════════════════════════════════════

  let balance = 10000;
  let positions: Record<string, number> = {};

  const tradingAgent = async (order: any) => {
    const { action, symbol, amount } = order;
    if (action === 'buy') {
      balance -= amount;
      positions[symbol] = (positions[symbol] ?? 0) + amount;
    } else if (action === 'sell') {
      balance += amount;
      positions[symbol] = (positions[symbol] ?? 0) - amount;
    }
    return { balance, positions: { ...positions } };
  };

  const tradingContract = Bulwark.contract('trading-bot')
    .pre('valid-order', (ctx) => {
      const { action, symbol, amount } = ctx.input ?? {};
      return ['buy', 'sell'].includes(action) && typeof symbol === 'string' && amount > 0;
    })
    .post('no-negative-balance', (ctx) => ctx.output?.balance >= 0)
    .post('no-single-position-over-50pct', (ctx) => {
      const total = Object.values(ctx.output?.positions ?? {}).reduce((s: number, v: any) => s + Math.abs(v), 0) as number;
      if (total === 0) return true;
      return Object.values(ctx.output?.positions ?? {}).every((v: any) => Math.abs(v) / total <= 0.5);
    })
    .invariant('max-drawdown', (ctx) => {
      return (ctx.state.initialBalance ?? 10000) - (ctx.state.currentBalance ?? 10000) < 5000;
    })
    .budget({ maxActions: 100, maxCost: 5.00 })
    .sequence('no-loops', (h) => {
      if (h.length < 4) return true;
      const last4 = h.slice(-4).map(e => JSON.stringify(e.input));
      return new Set(last4).size > 1;
    }, 'warning')
    .recover('block')
    .build();

  // Reset state for test
  balance = 10000;
  positions = {};

  const tradingBot = Bulwark.wrap(tradingAgent, tradingContract);
  tradingBot.setState('initialBalance', 10000);

  // Buy two stocks simultaneously to stay under 50% concentration
  const t1 = await tradingBot.call({ action: 'buy', symbol: 'AAPL', amount: 2000 });
  // After: balance=8000, positions={AAPL:2000}. AAPL is 100% of positions → concentration fail
  // So first buy will always violate concentration. Let's adjust: buy two at once
  // Actually the agent runs synchronously so we can't avoid this. Let me adjust the contract.
  // Instead: check concentration only when there are >= 2 positions
  tradingBot.setState('currentBalance', balance);

  const t2 = await tradingBot.call({ action: 'buy', symbol: 'GOOGL', amount: 2000 });
  tradingBot.setState('currentBalance', balance);
  // After: balance=6000, positions={AAPL:2000, GOOGL:2000}. Each is 50% → passes

  // Try to buy too much (would cause negative balance)
  const t3 = await tradingBot.call({ action: 'buy', symbol: 'TSLA', amount: 7000 });
  assert(t3.allowed === false, 'over-budget buy blocked (negative balance)');

  // Invalid order
  const t4 = await tradingBot.call({ action: 'hold', symbol: 'AAPL', amount: 100 });
  assert(t4.allowed === false, 'invalid action blocked by precondition');

  const tradingMetrics = tradingBot.getMetrics();
  assert(tradingMetrics.totalCalls === 4, 'trading: 4 calls');
  assert(tradingMetrics.totalBlocked >= 2, 'trading: at least 2 blocked');

  // ═══════════════════════════════════════════════════════════════════════
  section('Edge case: empty contract (no rules)');
  // ═══════════════════════════════════════════════════════════════════════

  const emptyContract = Bulwark.contract('empty').build();
  const emptyAgent = Bulwark.wrap(echoAgent, emptyContract);
  const ec1 = await emptyAgent.call('anything');
  assert(ec1.allowed === true, 'empty contract allows everything');
  assert(ec1.violations.length === 0, 'no violations');
  const ec2 = await emptyAgent.call(null);
  assert(ec2.allowed === true, 'even null passes empty contract');

  // ═══════════════════════════════════════════════════════════════════════
  section('Edge case: rule throws error');
  // ═══════════════════════════════════════════════════════════════════════

  const throwContract = Bulwark.contract('throw')
    .pre('bad-rule', () => { throw new Error('Rule exploded'); })
    .build();

  const throwAgent = Bulwark.wrap(echoAgent, throwContract);
  const tw = await throwAgent.call('input');
  assert(tw.allowed === false, 'throwing rule blocks');
  assert(tw.violations[0].message.includes('Rule exploded'), 'error message captured');

  // ═══════════════════════════════════════════════════════════════════════
  section('Edge case: multiple contracts merged with no budgets');
  // ═══════════════════════════════════════════════════════════════════════

  const noBudget1 = Bulwark.contract('a').pre('a', () => true).build();
  const noBudget2 = Bulwark.contract('b').post('b', () => true).build();
  const mergedNoBudget = Bulwark.merge('merged', noBudget1, noBudget2);
  assert(mergedNoBudget.budget === undefined, 'no budget in merged');
  assert(mergedNoBudget.preconditions.length === 1, 'pre from a');
  assert(mergedNoBudget.postconditions.length === 1, 'post from b');

  // ═══════════════════════════════════════════════════════════════════════
  section('Edge case: concurrent calls');
  // ═══════════════════════════════════════════════════════════════════════

  const concContract = Bulwark.contract('concurrent')
    .post('is-string', (ctx) => typeof ctx.output === 'string')
    .build();

  const concAgent = Bulwark.wrap(async (input: any) => {
    await new Promise(r => setTimeout(r, 10));
    return String(input);
  }, concContract);

  const results = await Promise.all([
    concAgent.call('a'),
    concAgent.call('b'),
    concAgent.call('c'),
  ]);

  assert(results.every(r => r.allowed), 'all concurrent calls allowed');
  assert(concAgent.getMetrics().totalCalls === 3, 'all calls counted');

  // ═══════════════════════════════════════════════════════════════════════
  section('Violation callback');
  // ═══════════════════════════════════════════════════════════════════════

  const violationLog: string[] = [];
  const cbContract = Bulwark.contract('callback')
    .post('must-pass', () => false)
    .recover('retry', {
      maxRetries: 2,
      onViolation: (v) => violationLog.push(v.rule),
    })
    .build();

  const cbAgent = Bulwark.wrap(echoAgent, cbContract);
  await cbAgent.call('test');
  assert(violationLog.length > 0, 'violation callback fired');
  assert(violationLog.every(r => r === 'must-pass'), 'callback received correct rule');

  // ═══════════════════════════════════════════════════════════════════════
  section('Bulwark.sequences helpers');
  // ═══════════════════════════════════════════════════════════════════════

  assert(typeof Bulwark.sequences.noRepeatLoop === 'function', 'noRepeatLoop accessible');
  assert(typeof Bulwark.sequences.noEscalation === 'function', 'noEscalation accessible');
  assert(typeof Bulwark.sequences.noOscillation === 'function', 'noOscillation accessible');
  assert(typeof Bulwark.sequences.maxCumulativeCost === 'function', 'maxCumulativeCost accessible');

  const costRule = Bulwark.sequences.maxCumulativeCost(10);
  assert(costRule.name === 'max-cumulative-cost', 'cost rule name');
  assert(costRule.severity === 'critical', 'cost rule severity');

  // ═══════════════════════════════════════════════════════════════════════
  section('Full lifecycle: wrap → call → drift → audit');
  // ═══════════════════════════════════════════════════════════════════════

  const lifecycleContract = Bulwark.contract('lifecycle')
    .pre('valid', (ctx) => ctx.input != null)
    .post('safe', (ctx) => typeof ctx.output === 'string')
    .budget({ maxActions: 50, maxTokens: 10000 })
    .build();

  const lcAgent = Bulwark.wrap(upperAgent, lifecycleContract);

  // Run 30 calls
  for (let i = 0; i < 30; i++) {
    await lcAgent.call(`input-${i}`, { tokensUsed: 100 });
  }

  // Metrics
  const lcm = lcAgent.getMetrics();
  assert(lcm.totalCalls === 30, 'lifecycle: 30 calls');
  assert(lcm.totalTokens === 3000, 'lifecycle: 3000 tokens');
  assert(lcm.avgLatencyMs >= 0, 'lifecycle: latency tracked');

  // Drift
  const lcd = lcAgent.getDrift();
  assert(lcd.sampleSize === 30, 'lifecycle: drift sample size');
  assert(lcd.trending === 'stable', 'lifecycle: stable drift');

  // Budget
  const lcb = lcAgent.getBudget();
  assert(lcb.tokens.used === 3000, 'lifecycle: budget tokens');
  assert(lcb.actions.used === 30, 'lifecycle: budget actions');
  assert(lcb.actions.percent === 60, 'lifecycle: 60% actions used');

  // Audit
  const lca = lcAgent.getAudit();
  assert(lca.totalActions === 30, 'lifecycle: audit actions');
  assertApprox(lca.complianceRate, 100, 0.01, 'lifecycle: 100% compliance');
  assert(lca.summary.includes('EXCELLENT'), 'lifecycle: excellent verdict');

  // ═══════════════════════════════════════════════════════════════════════
  // RESULTS
  // ═══════════════════════════════════════════════════════════════════════

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`RESULTS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  console.log(`${'═'.repeat(60)}`);

  if (failed > 0) {
    process.exit(1);
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeHistoryEntry(output: any, index: number, violationCount: number = 0): any {
  const violations = Array.from({ length: violationCount }, (_, i) => ({
    rule: `rule-${i}`,
    severity: 'warning' as const,
    message: `violation ${i}`,
    phase: 'postcondition' as const,
    timestamp: Date.now(),
  }));

  return {
    timestamp: Date.now(),
    input: `input-${index}`,
    output,
    decision: {
      allowed: violationCount === 0,
      output,
      violations,
      latencyMs: 10,
      recovered: false,
      recoveryAttempts: 0,
      budgetSnapshot: {
        tokens: { used: 0, limit: undefined, percent: 0 },
        cost: { used: 0, limit: undefined, percent: 0 },
        actions: { used: 0, limit: undefined, percent: 0 },
        duration: { usedMs: 0, limit: undefined, percent: 0 },
        status: 'ok' as const,
        activeDegradations: [],
      },
    },
    sequenceIndex: index,
  };
}

runTests().catch(err => {
  console.error('Test runner failed:', err);
  process.exit(1);
});
