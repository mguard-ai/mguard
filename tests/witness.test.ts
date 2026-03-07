/**
 * Tests for Witness Protocol (attestation + adaptive immunity)
 */

import {
  Bulwark, HashChain, AttestationEngine, ImmuneSystem,
} from '../src/index';

let passed = 0;
let failed = 0;
const errors: string[] = [];

function assert(condition: boolean, name: string) {
  if (condition) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.log(`  ✗ ${name}`);
    failed++;
    errors.push(name);
  }
}

function section(name: string) {
  console.log(`\n── ${name} ──`);
}

async function runTests() {

// ════════════════════════════════════════════════════════════════════════════
// Hash Chain
// ════════════════════════════════════════════════════════════════════════════

section('HashChain — basics');
{
  const chain = new HashChain('test-contract');
  assert(chain.length === 0, 'starts empty');
  assert(chain.getMerkleRoot().length === 64, 'empty chain has genesis Merkle root');

  const e1 = chain.append('input1', 'output1', 'allowed', []);
  assert(e1.index === 0, 'first entry index is 0');
  assert(e1.hash.length === 64, 'hash is 64 hex chars');
  assert(e1.prevHash === '0'.repeat(64), 'first entry prevHash is genesis');
  assert(e1.contractId === 'test-contract', 'contractId set');
  assert(e1.decision === 'allowed', 'decision recorded');
  assert(e1.violations.length === 0, 'no violations');

  const e2 = chain.append('input2', 'output2', 'blocked', ['rule-a']);
  assert(e2.index === 1, 'second entry index is 1');
  assert(e2.prevHash === e1.hash, 'second entry links to first');
  assert(e2.violations[0] === 'rule-a', 'violation recorded');
  assert(chain.length === 2, 'chain has 2 entries');
}

section('HashChain — integrity verification');
{
  const chain = new HashChain('verify-test');
  chain.append('a', 'b', 'allowed', []);
  chain.append('c', 'd', 'allowed', []);
  chain.append('e', 'f', 'blocked', ['fail']);

  const result = chain.verify();
  assert(result.valid === true, 'intact chain verifies');

  const entries = chain.getEntries();
  const tampered = [...entries];
  tampered[1] = { ...tampered[1], output: 'TAMPERED' };
  assert(chain.verify().valid === true, 'original chain still valid after getEntries copy');
}

section('HashChain — Merkle root');
{
  const chain1 = new HashChain('merkle-test');
  chain1.append('x', 'y', 'allowed', []);
  chain1.append('a', 'b', 'allowed', []);
  const root1 = chain1.getMerkleRoot();
  assert(root1.length === 64, 'Merkle root is 64 hex chars');

  const chain2 = new HashChain('merkle-test');
  chain2.append('x', 'y', 'allowed', []);
  chain2.append('a', 'b', 'allowed', []);
  assert(chain2.getMerkleRoot().length === 64, 'second chain also produces valid root');

  const chain3 = new HashChain('merkle-test');
  chain3.append('DIFFERENT', 'y', 'allowed', []);
  chain3.append('a', 'b', 'allowed', []);
  assert(chain3.getMerkleRoot() !== root1, 'different content = different Merkle root');
}

section('HashChain — reset');
{
  const chain = new HashChain('reset-test');
  chain.append('a', 'b', 'allowed', []);
  chain.append('c', 'd', 'allowed', []);
  assert(chain.length === 2, 'chain has entries before reset');
  chain.reset();
  assert(chain.length === 0, 'chain empty after reset');
  assert(chain.getMerkleRoot() === '0'.repeat(64), 'Merkle root is genesis after reset');
}

// ════════════════════════════════════════════════════════════════════════════
// Attestation Engine
// ════════════════════════════════════════════════════════════════════════════

section('AttestationEngine — certificate generation');
{
  const engine = new AttestationEngine('agent-1', 'test-secret');
  const chain = new HashChain('my-contract');

  chain.append('input1', 'output1', 'allowed', []);
  chain.append('input2', 'output2', 'allowed', []);
  chain.append('input3', undefined, 'blocked', ['rule-x']);

  const cert = engine.generateCertificate(chain, 'my-contract', 0.05, 0.3);

  assert(cert.version === '1.0', 'certificate version is 1.0');
  assert(cert.protocol === 'witness/1.0', 'protocol is witness/1.0');
  assert(cert.agentId === 'agent-1', 'agent ID correct');
  assert(cert.contractId === 'my-contract', 'contract ID correct');
  assert(cert.traceLength === 3, 'trace length is 3');
  assert(cert.compliance.totalActions === 3, 'total actions is 3');
  assert(cert.compliance.allowed === 2, 'allowed is 2');
  assert(cert.compliance.blocked === 1, 'blocked is 1');
  assert(Math.abs(cert.compliance.complianceRate - 66.67) < 0.1, 'compliance rate ~66.67%');
  assert(cert.behavioral.driftScore === 0.05, 'drift score recorded');
  assert(cert.behavioral.budgetUtilization === 0.3, 'budget utilization recorded');
  assert(cert.signature.length === 64, 'signature is 64 hex chars');
  assert(cert.traceRoot === chain.getMerkleRoot(), 'trace root matches chain');
  assert(cert.id.length > 0, 'certificate has ID');
  assert(cert.issuedAt > 0, 'issuedAt timestamp present');
  assert(cert.period.start > 0, 'period start present');
  assert(cert.period.end >= cert.period.start, 'period end >= start');
}

section('AttestationEngine — certificate verification');
{
  const engine = new AttestationEngine('agent-2', 'verify-secret');
  const chain = new HashChain('verify-contract');

  chain.append('a', 'b', 'allowed', []);
  chain.append('c', 'd', 'allowed', []);

  const cert = engine.generateCertificate(chain, 'verify-contract', 0, 0);
  const result = engine.verifyCertificate(cert, chain);

  assert(result.valid === true, 'valid certificate verifies');
  assert(result.signatureValid === true, 'signature valid');
  assert(result.chainIntegrity === true, 'chain integrity valid');
  assert(result.complianceVerified === true, 'compliance verified');
  assert(result.details.length >= 4, 'verification has multiple detail entries');
}

section('AttestationEngine — tampered certificate fails');
{
  const engine = new AttestationEngine('agent-3', 'tamper-secret');
  const chain = new HashChain('tamper-contract');

  chain.append('x', 'y', 'allowed', []);
  const cert = engine.generateCertificate(chain, 'tamper-contract', 0, 0);

  const tampered = { ...cert, compliance: { ...cert.compliance, complianceRate: 50 } };
  const result = engine.verifyCertificate(tampered, chain);

  assert(result.valid === false, 'tampered certificate fails verification');
  assert(result.signatureValid === false, 'tampered signature invalid');
}

section('AttestationEngine — different secret fails');
{
  const engine1 = new AttestationEngine('agent-4', 'secret-A');
  const engine2 = new AttestationEngine('agent-4', 'secret-B');
  const chain = new HashChain('cross-secret');

  chain.append('data', 'result', 'allowed', []);
  const cert = engine1.generateCertificate(chain, 'cross-secret', 0, 0);
  const result = engine2.verifyCertificate(cert, chain);

  assert(result.signatureValid === false, 'different secret = invalid signature');
}

section('AttestationEngine — empty chain');
{
  const engine = new AttestationEngine('agent-5', 'empty-secret');
  const chain = new HashChain('empty-contract');

  const cert = engine.generateCertificate(chain, 'empty-contract', 0, 0);
  assert(cert.compliance.totalActions === 0, 'empty chain: 0 actions');
  assert(cert.compliance.complianceRate === 100, 'empty chain: 100% compliance');
  assert(cert.traceLength === 0, 'empty chain: trace length 0');

  const result = engine.verifyCertificate(cert, chain);
  assert(result.valid === true, 'empty chain certificate is valid');
}

// ════════════════════════════════════════════════════════════════════════════
// Immune System
// ════════════════════════════════════════════════════════════════════════════

section('ImmuneSystem — learning phase');
{
  const immune = new ImmuneSystem({ learningPeriod: 5 });

  const status1 = immune.getStatus();
  assert(status1.established === false, 'not established initially');
  assert(status1.sampleCount === 0, 'sample count starts at 0');

  for (let i = 0; i < 4; i++) {
    const resp = immune.evaluate(`input-${i}`, `output-${i}`, [], 10);
    assert(resp.threat === false, `learning phase call ${i}: no threat`);
    assert(resp.response === 'allow', `learning phase call ${i}: allow`);
  }

  assert(immune.getStatus().established === false, 'not established after 4 samples');

  immune.evaluate('input-4', 'output-4', [], 10);
  assert(immune.getStatus().established === true, 'established after 5 samples');
  assert(immune.getStatus().sampleCount === 5, 'sample count is 5');
}

section('ImmuneSystem — threat memory');
{
  const immune = new ImmuneSystem({ learningPeriod: 3 });

  for (let i = 0; i < 3; i++) {
    immune.evaluate('normal', 'ok', [], 10);
  }

  immune.recordThreat('malicious-input', 'critical');
  assert(immune.getThreats().length === 1, 'one threat recorded');

  const threat = immune.getThreats()[0];
  assert(threat.severity === 'critical', 'threat severity is critical');
  assert(threat.occurrences === 1, 'threat seen once');

  immune.recordThreat('malicious-input', 'warning');
  assert(immune.getThreats().length === 1, 'still one threat (deduplicated)');
  assert(immune.getThreats()[0].occurrences === 2, 'threat seen twice');
  assert(immune.getThreats()[0].severity === 'critical', 'severity stays critical');
}

section('ImmuneSystem — known threat detection');
{
  const immune = new ImmuneSystem({ learningPeriod: 3 });

  for (let i = 0; i < 3; i++) {
    immune.evaluate('normal', 'ok', [], 10);
  }

  immune.recordThreat('bad-input', 'critical');

  const resp = immune.evaluate('bad-input', 'whatever', [], 10);
  assert(resp.threat === true, 'known threat detected');
  assert(resp.threatType === 'known', 'threat type is known');
  assert(resp.response === 'block', 'response is block for critical threat');
  assert(resp.newThreat === false, 'not a new threat');
}

section('ImmuneSystem — antibody export/import');
{
  const immune1 = new ImmuneSystem({ learningPeriod: 3 });
  const immune2 = new ImmuneSystem({ learningPeriod: 3 });

  for (let i = 0; i < 3; i++) immune1.evaluate('normal', 'ok', [], 10);
  immune1.recordThreat('attack-pattern', 'critical');
  immune1.recordThreat('attack-pattern', 'critical');

  const antibodies = immune1.exportAntibodies('agent-1');
  assert(antibodies.length === 1, 'one antibody exported');
  assert(antibodies[0].source === 'agent-1', 'antibody source is agent-1');
  assert(antibodies[0].effectiveness >= 0.5, 'antibody has effectiveness');

  const imported = immune2.importAntibodies(antibodies);
  assert(imported === 1, 'one antibody imported');
  assert(immune2.getStatus().antibodyCount === 1, 'agent 2 has 1 antibody');

  for (let i = 0; i < 3; i++) immune2.evaluate('safe', 'ok', [], 10);

  const resp = immune2.evaluate('attack-pattern', 'whatever', [], 10);
  assert(resp.threat === true, 'imported antibody detects threat');
  assert(resp.threatType === 'known', 'detected via antibody');
}

section('ImmuneSystem — duplicate antibody import');
{
  const immune = new ImmuneSystem();
  const antibodies: any[] = [
    { id: 'ab-1', pattern: 'p1', description: 'test', source: 'a', effectiveness: 0.8, created: Date.now(), uses: 0 },
    { id: 'ab-2', pattern: 'p1', description: 'test', source: 'b', effectiveness: 0.9, created: Date.now(), uses: 0 },
  ];

  const imported = immune.importAntibodies(antibodies);
  assert(imported === 1, 'duplicate pattern not imported twice');
}

section('ImmuneSystem — reset');
{
  const immune = new ImmuneSystem({ learningPeriod: 3 });
  for (let i = 0; i < 3; i++) immune.evaluate('x', 'y', [], 10);
  immune.recordThreat('bad', 'critical');

  assert(immune.getStatus().established === true, 'established before reset');
  assert(immune.getThreats().length === 1, 'has threats before reset');

  immune.reset();
  assert(immune.getStatus().established === false, 'not established after reset');
  assert(immune.getStatus().sampleCount === 0, 'sample count 0 after reset');
  assert(immune.getThreats().length === 0, 'no threats after reset');
}

section('ImmuneSystem — anomaly detection');
{
  const immune = new ImmuneSystem({ learningPeriod: 10 });

  for (let i = 0; i < 15; i++) {
    immune.evaluate({ type: 'query', text: 'hello' }, 'response', [], 10);
  }

  assert(immune.getStatus().established === true, 'baseline established');

  const normalResp = immune.evaluate({ type: 'query', text: 'hello' }, 'response', [], 10);
  assert(normalResp.threat === false, 'normal pattern not flagged');

  const highViolResp = immune.evaluate(
    { type: 'query', text: 'hello' }, 'response',
    ['v1', 'v2', 'v3', 'v4', 'v5'], 10,
  );
  assert(highViolResp.confidence !== undefined, 'anomaly response has confidence');
}

// ════════════════════════════════════════════════════════════════════════════
// Integration — HarnessedAgent with attestation + immunity
// ════════════════════════════════════════════════════════════════════════════

section('Integration — trace chain populated');
{
  const contract = Bulwark.contract('trace-test')
    .pre('valid', ctx => ctx.input !== null)
    .recover('block')
    .build();

  const agent = async (input: any) => `processed: ${input}`;
  const bot = Bulwark.wrap(agent, contract);

  await bot.call('hello');
  await bot.call('world');

  const trace = bot.getTraceChain();
  assert(trace.length === 2, 'trace chain has 2 entries');
  assert(trace[0].decision === 'allowed', 'first entry allowed');
  assert(trace[0].hash.length === 64, 'first entry has hash');
  assert(trace[1].prevHash === trace[0].hash, 'second entry links to first');
}

section('Integration — attestation certificate');
{
  const contract = Bulwark.contract('attest-test')
    .pre('non-empty', ctx => ctx.input !== '')
    .recover('block')
    .build();

  const agent = async (input: any) => `result: ${input}`;
  const bot = Bulwark.wrap(agent, contract);

  await bot.call('hello');
  await bot.call('world');
  const blocked = await bot.call('');

  assert(blocked.allowed === false, 'empty input blocked');

  const cert = bot.attest();
  assert(cert.protocol === 'witness/1.0', 'certificate uses witness protocol');
  assert(cert.compliance.totalActions === 3, 'certificate shows 3 actions');
  assert(cert.compliance.allowed === 2, 'certificate shows 2 allowed');
  assert(cert.compliance.blocked === 1, 'certificate shows 1 blocked');
  assert(cert.traceRoot.length === 64, 'certificate has Merkle root');
  assert(cert.signature.length === 64, 'certificate has signature');

  const verification = bot.verifyAttestation(cert);
  assert(verification.valid === true, 'certificate verifies successfully');
  assert(verification.signatureValid === true, 'signature valid');
  assert(verification.chainIntegrity === true, 'chain integrity valid');
}

section('Integration — decision includes trace entry');
{
  const contract = Bulwark.contract('decision-trace')
    .pre('ok', () => true)
    .recover('block')
    .build();

  const agent = async (input: any) => input;
  const bot = Bulwark.wrap(agent, contract);

  const result = await bot.call('test');
  assert(result.traceEntry !== undefined, 'decision has trace entry');
  assert(result.traceEntry!.hash.length === 64, 'trace entry has hash');
  assert(result.traceEntry!.decision === 'allowed', 'trace entry shows allowed');
}

section('Integration — decision includes immune response');
{
  const contract = Bulwark.contract('immune-decision')
    .pre('ok', () => true)
    .recover('block')
    .build();

  const agent = async (input: any) => input;
  const bot = Bulwark.wrap(agent, contract);

  const result = await bot.call('test');
  assert(result.immuneResponse !== undefined, 'decision has immune response');
  assert(result.immuneResponse!.threat === false, 'no threat on first call');
  assert(result.immuneResponse!.response === 'allow', 'immune response is allow');
}

section('Integration — immune system learns and detects threats');
{
  const contract = Bulwark.contract('immune-learn')
    .pre('no-injection', ctx => !String(ctx.input).includes('INJECT'))
    .recover('block')
    .build();

  const agent = async (input: any) => `safe: ${input}`;
  const bot = Bulwark.wrap(agent, contract);

  for (let i = 0; i < 20; i++) {
    await bot.call(`query-${i}`);
  }

  const status = bot.getImmuneStatus();
  assert(status.established === true, 'immune system baseline established');
  assert(status.sampleCount >= 20, 'sample count >= 20');

  const bad = await bot.call('INJECT malicious payload');
  assert(bad.allowed === false, 'injection blocked by contract');

  const statusAfter = bot.getImmuneStatus();
  assert(statusAfter.knownThreats >= 1, 'threat recorded in immune memory');
}

section('Integration — antibody sharing between agents');
{
  const contract = Bulwark.contract('antibody-share')
    .pre('safe', ctx => ctx.input !== 'ATTACK')
    .recover('block')
    .build();

  const agent = async (input: any) => input;

  const agentA = Bulwark.wrap(agent, contract);
  for (let i = 0; i < 20; i++) await agentA.call('normal');
  await agentA.call('ATTACK');
  await agentA.call('ATTACK');

  const antibodies = agentA.exportAntibodies();
  assert(antibodies.length >= 1, 'agent A exports antibodies');

  const agentB = Bulwark.wrap(agent, contract);
  const imported = agentB.importAntibodies(antibodies);
  assert(imported >= 1, 'agent B imports antibodies from A');

  const immuneB = agentB.getImmuneStatus();
  assert(immuneB.antibodyCount >= 1, 'agent B has imported antibodies');
}

section('Integration — reset clears attestation and immunity');
{
  const contract = Bulwark.contract('reset-all')
    .pre('ok', () => true)
    .recover('block')
    .build();

  const agent = async (input: any) => input;
  const bot = Bulwark.wrap(agent, contract);

  await bot.call('hello');
  await bot.call('world');

  assert(bot.getTraceChain().length === 2, 'trace chain has entries before reset');

  bot.reset();
  assert(bot.getTraceChain().length === 0, 'trace chain cleared after reset');

  const status = bot.getImmuneStatus();
  assert(status.sampleCount === 0, 'immune system reset');
  assert(status.established === false, 'immune baseline cleared');
}

section('Integration — certificate after blocked actions');
{
  const contract = Bulwark.contract('blocked-cert')
    .pre('positive', ctx => ctx.input > 0)
    .budget({ maxActions: 100 })
    .recover('block')
    .build();

  const agent = async (input: any) => input * 2;
  const bot = Bulwark.wrap(agent, contract);

  await bot.call(5);
  await bot.call(10);
  await bot.call(-1);
  await bot.call(3);
  await bot.call(0);

  const cert = bot.attest();
  assert(cert.compliance.totalActions === 5, '5 total actions in certificate');
  assert(cert.compliance.allowed === 3, '3 allowed');
  assert(cert.compliance.blocked === 2, '2 blocked');
  assert(cert.compliance.complianceRate === 60, '60% compliance rate');
  assert(cert.behavioral.driftScore >= 0, 'drift score present');

  const result = bot.verifyAttestation(cert);
  assert(result.valid === true, 'certificate with blocks still verifies');
}

// ════════════════════════════════════════════════════════════════════════════

console.log('\n════════════════════════════════════════════════════════════');
console.log(`WITNESS TESTS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log('════════════════════════════════════════════════════════════');

if (errors.length > 0) {
  console.log('\nFailed tests:');
  for (const e of errors) console.log(`  ✗ ${e}`);
}

process.exit(failed > 0 ? 1 : 0);

} // end runTests

runTests().catch(err => {
  console.error('Test runner failed:', err);
  process.exit(1);
});
