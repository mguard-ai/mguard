/**
 * Multi-Witness Consensus — tests.
 *
 * Covers: local nodes, consensus with full agreement, partial agreement,
 * compromised witnesses, offline witnesses, BFT quorum calculation,
 * and full integration with HarnessedAgent.
 */

import {
  generateWitnessKeys, witnessSign, deterministicStringify,
  LocalWitnessNode, WitnessNetwork, createWitnessCertificate,
} from '../src/witness';
import type { WitnessNode, WitnessCertificate, VerificationReceipt } from '../src/witness';
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

// Failing node — simulates a witness that is offline
class OfflineNode implements WitnessNode {
  async submitCertificate(): Promise<VerificationReceipt> {
    throw new Error('Connection refused');
  }
  async registerKey(): Promise<void> {
    throw new Error('Connection refused');
  }
  async getWitnessInfo() {
    return { witnessId: 'offline', publicKey: '', protocol: 'witness/1.0' };
  }
}

function makeValidCert(keys: { publicKey: string; privateKey: string }, overrides: Record<string, any> = {}): WitnessCertificate {
  const certBody = {
    id: `cert-${Math.random().toString(36).slice(2, 10)}`,
    version: '1.0' as const,
    protocol: 'witness/1.0' as const,
    agentId: 'test-agent',
    contractId: 'test-contract',
    period: { start: 1000, end: 2000 },
    traceRoot: 'abc123',
    traceLength: 10,
    compliance: { totalActions: 10, allowed: 9, blocked: 1, complianceRate: 90 },
    behavioral: { driftScore: 0.1, budgetUtilization: 0.5 },
    issuedAt: 3000,
    ...overrides,
  };

  const payload = deterministicStringify(certBody);
  const signature = witnessSign(payload, keys.privateKey);
  return { ...certBody, publicKey: keys.publicKey, signature };
}

async function runTests() {
  console.log('Multi-Witness Consensus — Test Suite\n');

  const keys = generateWitnessKeys();

  // ═══════════════════════════════════════════════════════════════════════
  section('BFT Quorum Calculation');

  assert(WitnessNetwork.bftQuorum(1) === 1, 'quorum(1) = 1');
  assert(WitnessNetwork.bftQuorum(2) === 2, 'quorum(2) = 2');
  assert(WitnessNetwork.bftQuorum(3) === 2, 'quorum(3) = 2');
  assert(WitnessNetwork.bftQuorum(4) === 3, 'quorum(4) = 3');
  assert(WitnessNetwork.bftQuorum(5) === 4, 'quorum(5) = 4');
  assert(WitnessNetwork.bftQuorum(6) === 4, 'quorum(6) = 4');
  assert(WitnessNetwork.bftQuorum(7) === 5, 'quorum(7) = 5');
  assert(WitnessNetwork.bftQuorum(9) === 6, 'quorum(9) = 6');
  assert(WitnessNetwork.bftQuorum(10) === 7, 'quorum(10) = 7');

  // ═══════════════════════════════════════════════════════════════════════
  section('LocalWitnessNode');

  const node = new LocalWitnessNode();
  const info = await node.getWitnessInfo();
  assert(info.protocol === 'witness/1.0', 'local node has protocol');
  assert(typeof info.witnessId === 'string', 'local node has ID');
  assert(typeof info.publicKey === 'string', 'local node has public key');

  await node.registerKey('test-agent', keys.publicKey);
  assert(node.registry.getKey('test-agent') === keys.publicKey, 'local node registers key');

  const cert = makeValidCert(keys);
  const receipt = await node.submitCertificate(cert);
  assert(receipt.result.valid === true, 'local node verifies certificate');

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — Full Agreement (5/5)');

  const network5 = new WitnessNetwork({ quorum: 3 });
  for (let i = 0; i < 5; i++) network5.addNode(new LocalWitnessNode());
  assert(network5.nodeCount === 5, '5 nodes in network');

  await network5.registerKeyOnAll('test-agent', keys.publicKey);

  const cert5 = makeValidCert(keys);
  const result5 = await network5.submitForConsensus(cert5);

  assert(result5.consensus === true, 'consensus reached');
  assert(result5.agreeing === 5, 'all 5 agree');
  assert(result5.dissenting === 0, '0 dissenting');
  assert(result5.unreachable === 0, '0 unreachable');
  assert(result5.quorum === 3, 'quorum is 3');
  assert(result5.receipts.length === 5, '5 receipts');
  assert(result5.witnessResults.length === 5, '5 witness results');
  assert(result5.certificateId === cert5.id, 'correct certificate ID');
  assert(result5.agentId === 'test-agent', 'correct agent ID');

  // All witness IDs should be different
  const witnessIds = result5.witnessResults.map(r => r.witnessId);
  const uniqueIds = new Set(witnessIds);
  assert(uniqueIds.size === 5, 'all 5 witnesses have unique IDs');

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — Compromised Witness (4/5 agree)');

  const networkCompromised = new WitnessNetwork({ quorum: 3 });
  const nodes = [];
  for (let i = 0; i < 5; i++) {
    const n = new LocalWitnessNode();
    nodes.push(n);
    networkCompromised.addNode(n);
  }

  // Register correct key on 4 nodes
  const correctKeys = generateWitnessKeys();
  const wrongKeys = generateWitnessKeys();
  for (let i = 0; i < 5; i++) {
    await nodes[i].registerKey('victim-agent', correctKeys.publicKey);
  }
  // Compromise node 2: register wrong key
  await nodes[2].registerKey('victim-agent', wrongKeys.publicKey);

  const certCompromised = makeValidCert(correctKeys, { agentId: 'victim-agent' });
  const resultCompromised = await networkCompromised.submitForConsensus(certCompromised);

  assert(resultCompromised.consensus === true, 'consensus reached despite compromised witness');
  assert(resultCompromised.agreeing === 4, '4 agree');
  assert(resultCompromised.dissenting === 1, '1 dissents (compromised)');
  assert(resultCompromised.unreachable === 0, '0 unreachable');

  // The dissenting witness should have INVALID details
  const dissentingWitness = resultCompromised.witnessResults.find(r => !r.valid);
  assert(dissentingWitness !== undefined, 'found dissenting witness');
  assert(
    dissentingWitness!.details.some(d => d.includes('DOES NOT MATCH') || d.includes('INVALID')),
    'dissenting witness gives reason',
  );

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — Offline Witnesses (3/5 reachable)');

  const networkPartial = new WitnessNetwork({ quorum: 3, timeout: 100 });
  for (let i = 0; i < 3; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey('test-agent', keys.publicKey);
    networkPartial.addNode(n);
  }
  networkPartial.addNode(new OfflineNode());
  networkPartial.addNode(new OfflineNode());

  const certPartial = makeValidCert(keys);
  const resultPartial = await networkPartial.submitForConsensus(certPartial);

  assert(resultPartial.consensus === true, 'consensus reached with 3/5');
  assert(resultPartial.agreeing === 3, '3 agree');
  assert(resultPartial.unreachable === 2, '2 unreachable');
  assert(resultPartial.dissenting === 0, '0 dissenting');

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — Quorum NOT Met (2/5 reachable)');

  const networkDown = new WitnessNetwork({ quorum: 3, timeout: 100 });
  for (let i = 0; i < 2; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey('test-agent', keys.publicKey);
    networkDown.addNode(n);
  }
  networkDown.addNode(new OfflineNode());
  networkDown.addNode(new OfflineNode());
  networkDown.addNode(new OfflineNode());

  const certDown = makeValidCert(keys);
  const resultDown = await networkDown.submitForConsensus(certDown);

  assert(resultDown.consensus === false, 'consensus NOT reached');
  assert(resultDown.agreeing === 2, '2 agree');
  assert(resultDown.unreachable === 3, '3 unreachable');

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — Invalid Certificate (unanimous rejection)');

  const networkReject = new WitnessNetwork({ quorum: 3 });
  for (let i = 0; i < 5; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey('test-agent', keys.publicKey);
    networkReject.addNode(n);
  }

  // Submit a tampered certificate
  const tampered = makeValidCert(keys);
  (tampered as any).compliance.complianceRate = 999;
  // Signature won't match the tampered body

  const resultReject = await networkReject.submitForConsensus(tampered);
  assert(resultReject.consensus === false, 'consensus NOT reached for invalid cert');
  assert(resultReject.agreeing === 0, '0 agree');
  assert(resultReject.dissenting === 5, 'all 5 reject');

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — BFT Quorum (tolerates floor(n/3) faults)');

  // With 7 nodes and BFT quorum (5), can tolerate 2 faults
  const network7 = new WitnessNetwork({ quorum: WitnessNetwork.bftQuorum(7), timeout: 100 });
  assert(WitnessNetwork.bftQuorum(7) === 5, 'BFT quorum for 7 nodes is 5');

  for (let i = 0; i < 5; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey('bft-agent', keys.publicKey);
    network7.addNode(n);
  }
  network7.addNode(new OfflineNode()); // fault 1
  network7.addNode(new OfflineNode()); // fault 2

  const certBft = makeValidCert(keys, { agentId: 'bft-agent' });
  const resultBft = await network7.submitForConsensus(certBft);
  assert(resultBft.consensus === true, 'BFT: consensus with 5/7 (tolerating 2 faults)');
  assert(resultBft.agreeing === 5, 'BFT: 5 agreeing');
  assert(resultBft.unreachable === 2, 'BFT: 2 faulty');

  // 3 faults should break consensus
  const network7b = new WitnessNetwork({ quorum: WitnessNetwork.bftQuorum(7), timeout: 100 });
  for (let i = 0; i < 4; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey('bft-agent', keys.publicKey);
    network7b.addNode(n);
  }
  network7b.addNode(new OfflineNode());
  network7b.addNode(new OfflineNode());
  network7b.addNode(new OfflineNode());

  const certBft2 = makeValidCert(keys, { agentId: 'bft-agent' });
  const resultBft2 = await network7b.submitForConsensus(certBft2);
  assert(resultBft2.consensus === false, 'BFT: 3 faults breaks consensus with 7 nodes');
  assert(resultBft2.agreeing === 4, 'BFT: only 4 agreeing');

  // ═══════════════════════════════════════════════════════════════════════
  section('Network Management');

  const networkMgmt = new WitnessNetwork({ quorum: 2 });
  assert(networkMgmt.nodeCount === 0, 'starts empty');

  const n1 = new LocalWitnessNode();
  const n2 = new LocalWitnessNode();
  networkMgmt.addNode(n1);
  networkMgmt.addNode(n2);
  assert(networkMgmt.nodeCount === 2, '2 nodes after adding');

  const removed = networkMgmt.removeNode(0);
  assert(removed !== undefined, 'removed node returned');
  assert(networkMgmt.nodeCount === 1, '1 node after removing');

  const allNodes = networkMgmt.getNodes();
  assert(allNodes.length === 1, 'getNodes returns correct count');

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — Single Node');

  const network1 = new WitnessNetwork({ quorum: 1 });
  const singleNode = new LocalWitnessNode();
  singleNode.registry.registerKey('test-agent', keys.publicKey);
  network1.addNode(singleNode);

  const cert1 = makeValidCert(keys);
  const result1 = await network1.submitForConsensus(cert1);
  assert(result1.consensus === true, 'single node consensus');
  assert(result1.agreeing === 1, 'single node agrees');

  // ═══════════════════════════════════════════════════════════════════════
  section('Consensus — Multiple Certificates');

  const networkMulti = new WitnessNetwork({ quorum: 2 });
  for (let i = 0; i < 3; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey('multi-agent', keys.publicKey);
    networkMulti.addNode(n);
  }

  const certA = makeValidCert(keys, { agentId: 'multi-agent', id: 'cert-A' });
  const certB = makeValidCert(keys, { agentId: 'multi-agent', id: 'cert-B' });
  const certC = makeValidCert(keys, { agentId: 'multi-agent', id: 'cert-C' });

  const [rA, rB, rC] = await Promise.all([
    networkMulti.submitForConsensus(certA),
    networkMulti.submitForConsensus(certB),
    networkMulti.submitForConsensus(certC),
  ]);

  assert(rA.consensus && rB.consensus && rC.consensus, 'all 3 certs reach consensus');
  assert(rA.certificateId === 'cert-A', 'cert A ID correct');
  assert(rB.certificateId === 'cert-B', 'cert B ID correct');
  assert(rC.certificateId === 'cert-C', 'cert C ID correct');

  // ═══════════════════════════════════════════════════════════════════════
  section('Full Integration — HarnessedAgent + Consensus');

  const agentKeys = generateWitnessKeys();
  const contract = Bulwark.contract('consensus-test')
    .pre('valid', ctx => ctx.input != null)
    .post('safe', ctx => typeof ctx.output === 'string')
    .budget({ maxActions: 50 })
    .build();

  const agent = Bulwark.wrap(async (x: string) => `ok: ${x}`, contract);

  // Run actions
  for (let i = 0; i < 10; i++) {
    await agent.call(`action-${i}`);
  }

  // Build 5-node network with BFT quorum
  const intNetwork = new WitnessNetwork({ quorum: WitnessNetwork.bftQuorum(5) });
  for (let i = 0; i < 5; i++) intNetwork.addNode(new LocalWitnessNode());
  await intNetwork.registerKeyOnAll(agent.sessionId, agentKeys.publicKey);

  // Generate and submit
  const intCert = createWitnessCertificate(agent, agentKeys);
  const intResult = await intNetwork.submitForConsensus(intCert);

  assert(intResult.consensus === true, 'integration: consensus reached');
  assert(intResult.agreeing === 5, 'integration: all 5 agree');
  assert(intResult.certificateId === intCert.id, 'integration: correct cert ID');

  // Each receipt should have different witness ID
  const intWitnessIds = new Set(intResult.witnessResults.map(r => r.witnessId));
  assert(intWitnessIds.size === 5, 'integration: 5 unique witness IDs');

  // Verify all witness counter-signatures are valid
  for (const receipt of intResult.receipts) {
    assert(receipt.result.valid === true, `integration: receipt from ${receipt.witnessId} is valid`);
    assert(receipt.result.signatureValid === true, `integration: sig from ${receipt.witnessId} valid`);
  }

  // Try with blocked actions too
  const strictContract = Bulwark.contract('strict')
    .pre('valid', ctx => ctx.input != null)
    .post('short', ctx => typeof ctx.output === 'string' && ctx.output.length < 3)
    .build();

  const strictAgent = Bulwark.wrap(async (x: string) => `long: ${x}`, strictContract);
  await strictAgent.call('a');
  await strictAgent.call('b');

  const strictCert = createWitnessCertificate(strictAgent, agentKeys);
  assert(strictCert.compliance.blocked === 2, 'integration: blocked counted');

  const strictResult = await intNetwork.submitForConsensus(strictCert);
  assert(strictResult.consensus === true, 'integration: cert with violations still reaches consensus');

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
  process.exitCode = 1;
});
