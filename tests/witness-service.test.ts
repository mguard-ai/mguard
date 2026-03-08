/**
 * Witness Verification Service — tests.
 *
 * Covers: Ed25519 crypto, certificate registry, HTTP server, full integration.
 */

import {
  generateWitnessKeys, witnessSign, witnessVerify, deterministicStringify,
  CertificateRegistry, createWitnessServer, WitnessClient,
  createWitnessCertificate,
} from '../src/witness';
import { Bulwark } from '../src/index';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(condition: boolean, msg: string) {
  if (condition) {
    passed++;
  } else {
    failed++;
    failures.push(msg);
    console.error(`  FAIL: ${msg}`);
  }
}

function section(name: string) {
  console.log(`\n── ${name} ${'─'.repeat(Math.max(0, 55 - name.length))}`);
}

async function runTests() {
  console.log('Witness Verification Service — Test Suite\n');

  // ═══════════════════════════════════════════════════════════════════════
  section('Ed25519 Crypto');

  const keys = generateWitnessKeys();
  assert(typeof keys.publicKey === 'string' && keys.publicKey.length > 0, 'generates public key');
  assert(typeof keys.privateKey === 'string' && keys.privateKey.length > 0, 'generates private key');
  assert(keys.publicKey !== keys.privateKey, 'public and private keys differ');

  const keys2 = generateWitnessKeys();
  assert(keys.publicKey !== keys2.publicKey, 'unique key pairs');

  const data = 'hello witness protocol';
  const sig = witnessSign(data, keys.privateKey);
  assert(typeof sig === 'string' && sig.length > 0, 'produces signature');
  assert(witnessVerify(data, sig, keys.publicKey), 'valid signature verifies');
  assert(!witnessVerify('tampered data', sig, keys.publicKey), 'tampered data fails verification');
  assert(!witnessVerify(data, sig, keys2.publicKey), 'wrong public key fails verification');

  // Different data → different signatures
  const sig2 = witnessSign('different data', keys.privateKey);
  assert(sig !== sig2, 'different data produces different signatures');

  // Same data + same key → same signature (Ed25519 is deterministic)
  const sigAgain = witnessSign(data, keys.privateKey);
  assert(sig === sigAgain, 'Ed25519 is deterministic');

  // Deterministic stringify
  const obj1 = { b: 2, a: 1, c: { z: 3, y: 4 } };
  const obj2 = { c: { y: 4, z: 3 }, a: 1, b: 2 };
  assert(deterministicStringify(obj1) === deterministicStringify(obj2), 'deterministic key ordering');

  const arr = [{ b: 2, a: 1 }, { d: 4, c: 3 }];
  assert(deterministicStringify(arr).includes('"a":1'), 'handles arrays with objects');
  assert(deterministicStringify(null) === 'null', 'handles null');
  assert(deterministicStringify(undefined) === undefined, 'handles undefined');
  assert(deterministicStringify(42) === '42', 'handles numbers');
  assert(deterministicStringify('hello') === '"hello"', 'handles strings');

  // ═══════════════════════════════════════════════════════════════════════
  section('Certificate Registry — Key Management');

  const registry = new CertificateRegistry();
  registry.registerKey('agent-1', keys.publicKey);
  assert(registry.getKey('agent-1') === keys.publicKey, 'registers and retrieves key');
  assert(registry.getKey('unknown') === undefined, 'undefined for unknown agent');

  registry.registerKey('agent-1', keys2.publicKey);
  assert(registry.getKey('agent-1') === keys2.publicKey, 'key update overwrites');
  registry.registerKey('agent-1', keys.publicKey); // restore

  // ═══════════════════════════════════════════════════════════════════════
  section('Certificate Registry — Submission & Verification');

  const certBody = {
    id: 'cert-001',
    version: '1.0' as const,
    protocol: 'witness/1.0' as const,
    agentId: 'agent-1',
    contractId: 'test-contract',
    period: { start: 1000, end: 2000 },
    traceRoot: 'abc123',
    traceLength: 10,
    compliance: { totalActions: 10, allowed: 9, blocked: 1, complianceRate: 90 },
    behavioral: { driftScore: 0.1, budgetUtilization: 0.5 },
    issuedAt: 3000,
  };

  const payload = deterministicStringify(certBody);
  const certSig = witnessSign(payload, keys.privateKey);
  const cert = { ...certBody, publicKey: keys.publicKey, signature: certSig };

  const receipt = registry.submitCertificate(cert);
  assert(receipt.result.valid === true, 'valid certificate accepted');
  assert(receipt.result.signatureValid === true, 'signature verified');
  assert(receipt.result.complianceValid === true, 'compliance verified');
  assert(receipt.certificateId === 'cert-001', 'correct certificate ID');
  assert(receipt.agentId === 'agent-1', 'correct agent ID');
  assert(receipt.contractId === 'test-contract', 'correct contract ID');
  assert(receipt.witnessId === registry.getWitnessId(), 'has witness ID');
  assert(typeof receipt.verification.signature === 'string', 'has counter-signature');
  assert(receipt.verification.checks.length > 0, 'has verification checks');
  assert(receipt.result.details.length > 0, 'has result details');

  // Retrieve from registry
  const entry = registry.getCertificate('cert-001');
  assert(entry !== undefined, 'stored in registry');
  assert(entry!.certificate.witnessVerifications?.length === 1, 'has witness verification');
  assert(entry!.receipt.result.valid === true, 'receipt shows valid');

  // Agent certificates query
  const agentCerts = registry.getAgentCertificates('agent-1');
  assert(agentCerts.length === 1, 'found 1 certificate for agent');
  assert(agentCerts[0].certificate.id === 'cert-001', 'correct certificate');

  // ═══════════════════════════════════════════════════════════════════════
  section('Certificate Registry — Rejection Cases');

  // Invalid signature
  const badCert = { ...cert, id: 'cert-bad-sig', signature: 'definitely-not-valid' };
  let badReceipt;
  try {
    badReceipt = registry.submitCertificate(badCert);
  } catch {
    badReceipt = { result: { valid: false } };
  }
  assert(badReceipt.result.valid === false, 'invalid signature rejected');

  // Tampered body (signature no longer matches)
  const tamperedCert = {
    ...cert,
    id: 'cert-tampered',
    compliance: { ...certBody.compliance, complianceRate: 100 },
  };
  const tamperedReceipt = registry.submitCertificate(tamperedCert);
  assert(tamperedReceipt.result.valid === false, 'tampered certificate rejected');

  // Wrong public key (key doesn't match registered)
  const wrongKeyCert = { ...cert, id: 'cert-wrong-key', publicKey: keys2.publicKey };
  const wrongKeyReceipt = registry.submitCertificate(wrongKeyCert);
  assert(wrongKeyReceipt.result.valid === false, 'wrong public key rejected');

  // Inconsistent stats (allowed + blocked != total)
  const inconsistentBody = {
    ...certBody,
    id: 'cert-inconsistent',
    compliance: { totalActions: 10, allowed: 5, blocked: 3, complianceRate: 50 },
  };
  const inconsistentPayload = deterministicStringify(inconsistentBody);
  const inconsistentSig = witnessSign(inconsistentPayload, keys.privateKey);
  const inconsistentCert = { ...inconsistentBody, publicKey: keys.publicKey, signature: inconsistentSig };
  const inconsistentReceipt = registry.submitCertificate(inconsistentCert);
  assert(inconsistentReceipt.result.complianceValid === false, 'inconsistent stats detected');

  // Inconsistent trace length
  const badTraceBody = {
    ...certBody,
    id: 'cert-bad-trace',
    traceLength: 999,
  };
  const badTracePayload = deterministicStringify(badTraceBody);
  const badTraceSig = witnessSign(badTracePayload, keys.privateKey);
  const badTraceCert = { ...badTraceBody, publicKey: keys.publicKey, signature: badTraceSig };
  const badTraceReceipt = registry.submitCertificate(badTraceCert);
  assert(badTraceReceipt.result.complianceValid === false, 'mismatched trace length detected');

  // Bad temporal data (issuedAt before period end)
  const badTemporalBody = {
    ...certBody,
    id: 'cert-bad-time',
    issuedAt: 500,  // before period.end (2000)
  };
  const badTemporalPayload = deterministicStringify(badTemporalBody);
  const badTemporalSig = witnessSign(badTemporalPayload, keys.privateKey);
  const badTemporalCert = { ...badTemporalBody, publicKey: keys.publicKey, signature: badTemporalSig };
  const badTemporalReceipt = registry.submitCertificate(badTemporalCert);
  assert(badTemporalReceipt.result.complianceValid === false, 'bad temporal data detected');

  // Compliance rate out of range
  const badRateBody = {
    ...certBody,
    id: 'cert-bad-rate',
    compliance: { totalActions: 10, allowed: 9, blocked: 1, complianceRate: 150 },
  };
  const badRatePayload = deterministicStringify(badRateBody);
  const badRateSig = witnessSign(badRatePayload, keys.privateKey);
  const badRateCert = { ...badRateBody, publicKey: keys.publicKey, signature: badRateSig };
  const badRateReceipt = registry.submitCertificate(badRateCert);
  assert(badRateReceipt.result.complianceValid === false, 'out-of-range compliance rate detected');

  // Only valid cert should be stored
  assert(registry.getAgentCertificates('agent-1').length === 1, 'invalid certs not stored');

  // ═══════════════════════════════════════════════════════════════════════
  section('Certificate Registry — Trust on First Use');

  const newAgentKeys = generateWitnessKeys();
  const tofuBody = {
    ...certBody,
    id: 'cert-tofu',
    agentId: 'new-agent-tofu',
  };
  const tofuPayload = deterministicStringify(tofuBody);
  const tofuSig = witnessSign(tofuPayload, newAgentKeys.privateKey);
  const tofuCert = { ...tofuBody, publicKey: newAgentKeys.publicKey, signature: tofuSig };

  // No pre-registration — trust on first use
  assert(registry.getKey('new-agent-tofu') === undefined, 'new agent not registered');
  const tofuReceipt = registry.submitCertificate(tofuCert);
  assert(tofuReceipt.result.valid === true, 'TOFU: first cert accepted');
  assert(registry.getKey('new-agent-tofu') === newAgentKeys.publicKey, 'TOFU: key auto-registered');

  // Second cert with different key should fail
  const otherKeys = generateWitnessKeys();
  const tofuBody2 = { ...certBody, id: 'cert-tofu-2', agentId: 'new-agent-tofu' };
  const tofuPayload2 = deterministicStringify(tofuBody2);
  const tofuSig2 = witnessSign(tofuPayload2, otherKeys.privateKey);
  const tofuCert2 = { ...tofuBody2, publicKey: otherKeys.publicKey, signature: tofuSig2 };
  const tofuReceipt2 = registry.submitCertificate(tofuCert2);
  assert(tofuReceipt2.result.valid === false, 'TOFU: different key rejected after registration');

  // ═══════════════════════════════════════════════════════════════════════
  section('Antibody Network');

  const antibodies = [
    { id: 'ab-1', pattern: 'hash1', description: 'threat1', source: 'agent-1', effectiveness: 0.9, created: Date.now(), uses: 3 },
    { id: 'ab-2', pattern: 'hash2', description: 'threat2', source: 'agent-1', effectiveness: 0.8, created: Date.now(), uses: 2 },
  ];
  const added = registry.submitAntibodies(antibodies);
  assert(added === 2, 'added 2 antibodies');
  assert(registry.getAntibodies().length === 2, 'retrieved 2 antibodies');

  // Deduplication
  const added2 = registry.submitAntibodies(antibodies);
  assert(added2 === 0, 'duplicates not re-added');
  assert(registry.getAntibodies().length === 2, 'count unchanged after dedup');

  // New antibody
  const added3 = registry.submitAntibodies([
    { id: 'ab-3', pattern: 'hash3', description: 'threat3', source: 'agent-2', effectiveness: 0.7, created: Date.now(), uses: 1 },
  ]);
  assert(added3 === 1, 'added 1 new antibody');
  assert(registry.getAntibodies().length === 3, 'now 3 total');

  // ═══════════════════════════════════════════════════════════════════════
  section('Network Stats');

  const stats = registry.getStats();
  assert(stats.totalCertificates === 2, '2 verified certificates');
  assert(stats.totalAgents === 2, '2 agents with certs');
  assert(stats.totalAntibodiesShared === 3, '3 shared antibodies');
  assert(stats.avgComplianceRate === 90, 'correct avg compliance');
  assert(stats.uptime > 0, 'uptime positive');
  assert(stats.totalVerifications >= 2, 'verifications counted');

  // ═══════════════════════════════════════════════════════════════════════
  section('Witness Counter-Signature Verification');

  const storedEntry = registry.getCertificate('cert-001')!;
  const wv = storedEntry.certificate.witnessVerifications![0];
  const counterPayload = deterministicStringify({
    certificateId: 'cert-001',
    valid: true,
    details: wv.checks,
    verifiedAt: wv.verifiedAt,
  });
  const counterValid = witnessVerify(counterPayload, wv.signature, wv.witnessPublicKey);
  assert(counterValid, 'witness counter-signature verifies independently');
  assert(wv.witnessPublicKey === registry.getWitnessPublicKey(), 'counter-sig uses witness public key');

  // ═══════════════════════════════════════════════════════════════════════
  section('HTTP Server');

  const testServer = createWitnessServer({ port: 0 });
  await testServer.start();
  const client = new WitnessClient(`http://localhost:${testServer.port}`);

  // Witness info
  const info = await client.getWitnessInfo();
  assert(info.protocol === 'witness/1.0', 'HTTP: witness protocol version');
  assert(typeof info.witnessId === 'string', 'HTTP: witness has ID');
  assert(typeof info.publicKey === 'string', 'HTTP: witness has public key');

  // Register key
  await client.registerKey('http-agent', keys.publicKey);

  // Submit valid certificate
  const httpBody = {
    ...certBody,
    id: 'cert-http-001',
    agentId: 'http-agent',
  };
  const httpPayload = deterministicStringify(httpBody);
  const httpSig = witnessSign(httpPayload, keys.privateKey);
  const httpCert = { ...httpBody, publicKey: keys.publicKey, signature: httpSig };

  const httpReceipt = await client.submitCertificate(httpCert as any);
  assert(httpReceipt.result.valid === true, 'HTTP: valid certificate accepted');
  assert(httpReceipt.result.signatureValid === true, 'HTTP: signature verified');
  assert(httpReceipt.result.complianceValid === true, 'HTTP: compliance verified');

  // Get certificate
  const retrieved = await client.getCertificate('cert-http-001');
  assert(retrieved.certificate.id === 'cert-http-001', 'HTTP: retrieved certificate');
  assert(retrieved.receipt.result.valid === true, 'HTTP: retrieved receipt valid');
  assert(retrieved.certificate.witnessVerifications!.length === 1, 'HTTP: has witness verification');

  // Agent certificates
  const agentResult = await client.getAgentCertificates('http-agent');
  assert(agentResult.certificates.length === 1, 'HTTP: agent certificates listed');

  // Submit invalid certificate
  const badHttpCert = { ...httpCert, id: 'cert-http-bad', signature: 'invalid' };
  let badHttpReceipt;
  try {
    badHttpReceipt = await client.submitCertificate(badHttpCert as any);
  } catch {
    badHttpReceipt = { result: { valid: false } };
  }
  assert(badHttpReceipt.result.valid === false, 'HTTP: invalid certificate rejected');

  // Share antibodies
  const httpAntibodies = [
    { id: 'ab-http-1', pattern: 'http-hash', description: 'http-threat', source: 'http-agent', effectiveness: 0.95, created: Date.now(), uses: 1 },
  ];
  const shareResult = await client.shareAntibodies(httpAntibodies);
  assert(shareResult.added === 1, 'HTTP: shared antibodies');

  // Fetch antibodies
  const fetched = await client.fetchAntibodies();
  assert(fetched.length === 1, 'HTTP: fetched antibodies');
  assert(fetched[0].pattern === 'http-hash', 'HTTP: correct antibody');

  // Stats
  const httpStats = await client.getStats();
  assert(httpStats.totalCertificates === 1, 'HTTP: stats certificates');
  assert(httpStats.totalAntibodiesShared === 1, 'HTTP: stats antibodies');

  // 404 for unknown certificate
  let notFoundError = false;
  try {
    await client.getCertificate('nonexistent');
  } catch {
    notFoundError = true;
  }
  assert(notFoundError, 'HTTP: 404 for unknown certificate');

  await testServer.stop();

  // ═══════════════════════════════════════════════════════════════════════
  section('Full Integration — HarnessedAgent to Witness Service');

  const agentKeys = generateWitnessKeys();
  const contract = Bulwark.contract('integration-test')
    .pre('valid', ctx => ctx.input != null)
    .post('safe', ctx => typeof ctx.output === 'string')
    .build();

  const harnessed = Bulwark.wrap(async (input: string) => `processed: ${input}`, contract);

  // Run actions
  await harnessed.call('hello');
  await harnessed.call('world');
  await harnessed.call('test');
  await harnessed.call('integration');
  await harnessed.call('complete');

  // Generate witness certificate
  const witnessCert = createWitnessCertificate(harnessed, agentKeys);
  assert(witnessCert.protocol === 'witness/1.0', 'Integration: protocol set');
  assert(witnessCert.publicKey === agentKeys.publicKey, 'Integration: has public key');
  assert(typeof witnessCert.signature === 'string', 'Integration: has Ed25519 signature');
  assert(witnessCert.compliance.totalActions === 5, 'Integration: correct action count');
  assert(witnessCert.compliance.allowed === 5, 'Integration: all allowed');
  assert(witnessCert.compliance.blocked === 0, 'Integration: none blocked');
  assert(witnessCert.compliance.complianceRate === 100, 'Integration: 100% compliance');
  assert(witnessCert.traceLength === 5, 'Integration: correct trace length');

  // Verify signature independently
  const { signature: certSig2, publicKey: certPk, witnessVerifications: _wv, ...verifyCertBody } = witnessCert;
  const verifyPayload = deterministicStringify(verifyCertBody);
  assert(witnessVerify(verifyPayload, certSig2, certPk), 'Integration: Ed25519 signature verifies');

  // Submit to a fresh registry
  const intRegistry = new CertificateRegistry();
  const intReceipt = intRegistry.submitCertificate(witnessCert);
  assert(intReceipt.result.valid === true, 'Integration: accepted by registry');
  assert(intReceipt.result.signatureValid === true, 'Integration: signature valid');
  assert(intReceipt.result.complianceValid === true, 'Integration: compliance valid');

  // Verify the registry stored it
  const stored = intRegistry.getCertificate(witnessCert.id);
  assert(stored !== undefined, 'Integration: stored in registry');
  assert(stored!.certificate.witnessVerifications!.length === 1, 'Integration: counter-signed');

  // Run with violations
  const strictContract = Bulwark.contract('strict-test')
    .pre('valid', ctx => ctx.input != null)
    .post('must-be-short', ctx => typeof ctx.output === 'string' && ctx.output.length < 5)
    .build();

  const strictAgent = Bulwark.wrap(async (input: string) => `long output: ${input}`, strictContract);
  await strictAgent.call('a');
  await strictAgent.call('b');

  const strictCert = createWitnessCertificate(strictAgent, agentKeys);
  assert(strictCert.compliance.blocked === 2, 'Integration: blocked actions counted');
  assert(strictCert.compliance.complianceRate === 0, 'Integration: 0% compliance');

  const strictReceipt = intRegistry.submitCertificate(strictCert);
  assert(strictReceipt.result.valid === true, 'Integration: cert with violations accepted');

  // ═══════════════════════════════════════════════════════════════════════
  section('End-to-End HTTP Integration');

  const e2eServer = createWitnessServer({ port: 0 });
  await e2eServer.start();
  const e2eClient = new WitnessClient(`http://localhost:${e2eServer.port}`);

  // Register + submit + verify over HTTP
  const e2eKeys = generateWitnessKeys();
  const e2eContract = Bulwark.contract('e2e-contract')
    .pre('valid', ctx => ctx.input != null)
    .build();
  const e2eAgent = Bulwark.wrap(async (x: any) => x, e2eContract);
  await e2eAgent.call('data1');
  await e2eAgent.call('data2');
  await e2eAgent.call('data3');

  await e2eClient.registerKey(e2eAgent.sessionId, e2eKeys.publicKey);
  const e2eCert = createWitnessCertificate(e2eAgent, e2eKeys);
  const e2eReceipt = await e2eClient.submitCertificate(e2eCert as any);
  assert(e2eReceipt.result.valid === true, 'E2E: certificate verified over HTTP');

  // Retrieve and verify counter-signature
  const e2eRetrieved = await e2eClient.getCertificate(e2eCert.id);
  const e2eWv = e2eRetrieved.certificate.witnessVerifications![0];
  const e2eCounterPayload = deterministicStringify({
    certificateId: e2eCert.id,
    valid: true,
    details: e2eWv.checks,
    verifiedAt: e2eWv.verifiedAt,
  });
  const e2eCounterValid = witnessVerify(e2eCounterPayload, e2eWv.signature, e2eWv.witnessPublicKey);
  assert(e2eCounterValid, 'E2E: witness counter-signature verifies');

  // Share antibodies from agent
  const e2eAntibodies = e2eAgent.exportAntibodies();
  // (may be empty if no threats encountered — that's fine)
  await e2eClient.shareAntibodies(e2eAntibodies);

  const e2eStats = await e2eClient.getStats();
  assert(e2eStats.totalCertificates === 1, 'E2E: stats show 1 certificate');

  await e2eServer.stop();

  // ═══════════════════════════════════════════════════════════════════════
  // Summary
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  Tests: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  if (failures.length > 0) {
    console.log(`\n  Failures:`);
    failures.forEach(f => console.log(`    - ${f}`));
  }
  console.log(`${'='.repeat(60)}\n`);
  process.exitCode = failed > 0 ? 1 : 0;
}

runTests().catch(err => {
  console.error('Test runner failed:', err);
  process.exit(1);
});
