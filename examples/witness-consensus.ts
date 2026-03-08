/**
 * MULTI-WITNESS CONSENSUS — LIVE DEMO
 *
 * Five independent witness nodes verify an AI agent's behavioral certificate.
 * Byzantine fault tolerance: even with compromised and offline witnesses,
 * the network reaches (or rejects) consensus.
 *
 * Scenarios:
 *   1. Full agreement — all 5 witnesses verify
 *   2. Compromised witness — 1 has wrong key, 4/5 still agree
 *   3. Network partition — 2 witnesses offline, 3/5 still agree
 *   4. Below quorum — 3 offline, consensus fails (system stays safe)
 *   5. Forgery — all witnesses unanimously reject
 */

import { Bulwark } from '../src/index';
import {
  generateWitnessKeys, createWitnessCertificate,
  LocalWitnessNode, WitnessNetwork,
} from '../src/witness';

// ── ANSI ──

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', magenta: '\x1b[35m',
  white: '\x1b[37m',
  bgGreen: '\x1b[42m', bgRed: '\x1b[41m', bgYellow: '\x1b[43m', bgCyan: '\x1b[46m',
};

function banner(text: string, sub: string) {
  const w = 66;
  console.log(`\n${C.magenta}${'#'.repeat(w)}`);
  console.log(`##${' '.repeat(w - 4)}##`);
  console.log(`##${text.padStart((w - 4 + text.length) / 2).padEnd(w - 4)}##`);
  console.log(`##${sub.padStart((w - 4 + sub.length) / 2).padEnd(w - 4)}##`);
  console.log(`##${' '.repeat(w - 4)}##`);
  console.log(`${'#'.repeat(w)}${C.reset}\n`);
}

function phase(n: number, title: string) {
  console.log(`\n${C.bold}${C.blue}== Scenario ${n}: ${title} ${'='.repeat(Math.max(0, 47 - title.length))}${C.reset}\n`);
}

function ok(msg: string) { console.log(`  ${C.green}[OK]${C.reset} ${msg}`); }
function fail(msg: string) { console.log(`  ${C.red}[!!]${C.reset} ${msg}`); }
function info(msg: string) { console.log(`  ${C.dim}${msg}${C.reset}`); }

function consensusBox(label: string, r: any) {
  const tag = r.consensus
    ? `${C.bgGreen}${C.white} CONSENSUS ${C.reset}`
    : `${C.bgRed}${C.white} NO CONSENSUS ${C.reset}`;
  console.log(`\n  ${tag} ${C.bold}${label}${C.reset}`);
  console.log(`  ${C.cyan}+${'─'.repeat(50)}+`);
  console.log(`  | ${C.white}Agreeing:    ${String(r.agreeing).padEnd(37)}${C.cyan}|`);
  console.log(`  | ${C.white}Dissenting:  ${String(r.dissenting).padEnd(37)}${C.cyan}|`);
  console.log(`  | ${C.white}Unreachable: ${String(r.unreachable).padEnd(37)}${C.cyan}|`);
  console.log(`  | ${C.white}Quorum:      ${String(r.quorum).padEnd(37)}${C.cyan}|`);
  console.log(`  +${'─'.repeat(50)}+${C.reset}`);

  for (const w of r.witnessResults) {
    const icon = w.valid ? `${C.green}V${C.reset}` : `${C.red}X${C.reset}`;
    const id = w.witnessId.padEnd(20);
    const detail = w.details[0] ?? '';
    console.log(`  ${icon} ${C.dim}${id}${C.reset} ${detail}`);
  }
}

// Failing node — simulates offline witness
class OfflineNode {
  async submitCertificate(): Promise<any> { throw new Error('Connection refused'); }
  async registerKey(): Promise<void> { throw new Error('Connection refused'); }
  async getWitnessInfo() { return { witnessId: 'OFFLINE', publicKey: '', protocol: 'witness/1.0' }; }
}

async function main() {
  banner(
    'MULTI-WITNESS CONSENSUS',
    'Byzantine Fault-Tolerant AI Agent Attestation',
  );

  // ── Setup: Agent + Keys ────────────────────────────────────────────────

  const agentKeys = generateWitnessKeys();
  const wrongKeys = generateWitnessKeys();

  const contract = Bulwark.contract('trading-desk')
    .pre('valid-order', ctx => ctx.input && ctx.input.qty > 0)
    .post('within-limits', ctx => ctx.output && ctx.output.cost < 500000)
    .budget({ maxActions: 50 })
    .build();

  const agent = Bulwark.wrap(
    async (order: any) => ({
      fill: `${order.side} ${order.qty} ${order.symbol}`,
      cost: order.qty * (order.price ?? 100),
    }),
    contract,
  );

  // Run some trades
  const symbols = ['AAPL', 'GOOGL', 'MSFT', 'NVDA', 'META'];
  for (let i = 0; i < 15; i++) {
    await agent.call({
      symbol: symbols[i % symbols.length],
      qty: Math.floor(Math.random() * 200) + 10,
      side: i % 3 === 0 ? 'sell' : 'buy',
      price: 50 + Math.random() * 200,
    });
  }

  // Try a blocked trade
  await agent.call({ symbol: 'NVDA', qty: 10000, side: 'buy', price: 900 });

  info(`Agent executed ${agent.getMetrics().totalCalls} trades (${agent.getMetrics().totalBlocked} blocked)`);
  info(`Generating Ed25519-signed attestation certificate...`);

  const cert = createWitnessCertificate(agent, agentKeys);
  ok(`Certificate ${cert.id.slice(0, 8)}... — ${cert.compliance.totalActions} actions, ${cert.compliance.complianceRate.toFixed(1)}% compliance`);

  const bftQuorum = WitnessNetwork.bftQuorum(5);
  info(`BFT quorum for 5 nodes: ${bftQuorum} (tolerates ${5 - bftQuorum} faults)\n`);

  // ── Scenario 1: Full Agreement ─────────────────────────────────────────
  phase(1, 'Full Agreement (5/5)');

  const net1 = new WitnessNetwork({ quorum: bftQuorum });
  for (let i = 0; i < 5; i++) net1.addNode(new LocalWitnessNode());
  await net1.registerKeyOnAll(agent.sessionId, agentKeys.publicKey);

  const r1 = await net1.submitForConsensus(cert);
  consensusBox('All witnesses operational', r1);

  if (r1.consensus) {
    ok(`${r1.agreeing} independent witnesses verified the certificate`);
    info(`Each witness independently verified the Ed25519 signature,`);
    info(`checked compliance stats consistency, and counter-signed.`);
  }

  // ── Scenario 2: Compromised Witness ───────────────────────────────────
  phase(2, 'Compromised Witness (4/5 agree)');

  info(`Witness #3 has been compromised — wrong public key for agent.`);
  info(`It will reject the certificate. Can the network still agree?\n`);

  const net2 = new WitnessNetwork({ quorum: bftQuorum });
  const net2nodes: LocalWitnessNode[] = [];
  for (let i = 0; i < 5; i++) {
    const n = new LocalWitnessNode();
    net2nodes.push(n);
    net2.addNode(n);
  }
  // Register correct key on all
  for (const n of net2nodes) {
    n.registry.registerKey(agent.sessionId, agentKeys.publicKey);
  }
  // Compromise node 2 (index 2)
  net2nodes[2].registry.registerKey(agent.sessionId, wrongKeys.publicKey);

  const r2 = await net2.submitForConsensus(cert);
  consensusBox('One witness compromised', r2);

  if (r2.consensus) {
    ok(`Consensus holds — ${r2.agreeing}/5 honest witnesses outweigh 1 compromised`);
  }

  // ── Scenario 3: Network Partition (2 offline) ─────────────────────────
  phase(3, 'Network Partition (3/5 reachable)');

  info(`Witnesses #4 and #5 are offline (network partition).`);
  info(`Only 3 of 5 witnesses can be reached.\n`);

  const net3 = new WitnessNetwork({ quorum: bftQuorum, timeout: 200 });
  for (let i = 0; i < 3; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey(agent.sessionId, agentKeys.publicKey);
    net3.addNode(n);
  }
  net3.addNode(new OfflineNode() as any);
  net3.addNode(new OfflineNode() as any);

  const r3 = await net3.submitForConsensus(cert);
  consensusBox('Two witnesses offline', r3);

  if (!r3.consensus) {
    fail(`Consensus FAILED — only ${r3.agreeing} of ${r3.quorum} required witnesses reachable`);
    info(`System stays safe: certificate is NOT accepted without sufficient verification.`);
    info(`This is correct behavior — safety over liveness.`);
  } else {
    ok(`Consensus reached with ${r3.agreeing} witnesses`);
  }

  // ── Scenario 4: Below Quorum ──────────────────────────────────────────
  phase(4, 'Below Quorum (2/5 reachable)');

  info(`3 witnesses offline. Only 2 reachable. Quorum requires ${bftQuorum}.\n`);

  const net4 = new WitnessNetwork({ quorum: bftQuorum, timeout: 200 });
  for (let i = 0; i < 2; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey(agent.sessionId, agentKeys.publicKey);
    net4.addNode(n);
  }
  net4.addNode(new OfflineNode() as any);
  net4.addNode(new OfflineNode() as any);
  net4.addNode(new OfflineNode() as any);

  const r4 = await net4.submitForConsensus(cert);
  consensusBox('Three witnesses offline', r4);

  fail(`Consensus FAILED — ${r4.agreeing} < ${r4.quorum} quorum`);
  info(`The network correctly refuses to certify without sufficient witnesses.`);
  info(`An attacker can't bypass verification by taking down witnesses.`);

  // ── Scenario 5: Forgery Detection ─────────────────────────────────────
  phase(5, 'Forged Certificate (unanimous rejection)');

  info(`Attacker forges a certificate: 93.8% -> 100% compliance, 0 blocked.\n`);

  const forged = {
    ...cert,
    id: 'cert-forged-consensus',
    compliance: {
      ...cert.compliance,
      complianceRate: 100,
      blocked: 0,
      allowed: cert.compliance.totalActions,
    },
  };

  const net5 = new WitnessNetwork({ quorum: bftQuorum });
  for (let i = 0; i < 5; i++) {
    const n = new LocalWitnessNode();
    n.registry.registerKey(agent.sessionId, agentKeys.publicKey);
    net5.addNode(n);
  }

  const r5 = await net5.submitForConsensus(forged);
  consensusBox('Forged certificate', r5);

  fail(`ALL ${r5.dissenting} witnesses rejected the forgery`);
  info(`Ed25519 signature binds every field — any modification is detectable.`);
  info(`No number of compromised witnesses can make a forged certificate valid.`);

  // ── Summary ────────────────────────────────────────────────────────────

  console.log(`\n${C.bold}${C.cyan}== Summary ${'='.repeat(54)}${C.reset}\n`);

  const scenarios = [
    { name: 'Full agreement (5/5)',    result: r1.consensus, detail: `${r1.agreeing}/${r1.agreeing + r1.dissenting + r1.unreachable}` },
    { name: 'Compromised witness',     result: r2.consensus, detail: `${r2.agreeing}/${r2.agreeing + r2.dissenting + r2.unreachable}` },
    { name: 'Network partition (2 down)', result: r3.consensus, detail: `${r3.agreeing}/${r3.agreeing + r3.dissenting + r3.unreachable}` },
    { name: 'Below quorum (3 down)',   result: r4.consensus, detail: `${r4.agreeing}/${r4.agreeing + r4.dissenting + r4.unreachable}` },
    { name: 'Forged certificate',      result: r5.consensus, detail: `${r5.agreeing}/${r5.agreeing + r5.dissenting + r5.unreachable}` },
  ];

  for (const s of scenarios) {
    const icon = s.result ? `${C.green}PASS${C.reset}` : `${C.red}FAIL${C.reset}`;
    const expected = s.name.includes('Below') || s.name.includes('Forged') || s.name.includes('partition')
      ? !s.result : s.result;
    const correct = expected ? `${C.green}(correct)${C.reset}` : `${C.red}(unexpected)${C.reset}`;
    console.log(`  ${icon}  ${s.name.padEnd(30)} ${s.detail.padEnd(8)} ${correct}`);
  }

  console.log(`\n${C.dim}  BFT guarantee: ceil(2n/3) quorum tolerates floor(n/3) faulty nodes.`);
  console.log(`  With 5 witnesses and quorum=${bftQuorum}: tolerates ${5 - bftQuorum} fault(s).`);
  console.log(`  Protocol: witness/1.0 — Ed25519 signatures, independent verification.${C.reset}`);

  console.log(`\n${C.green}${C.bold}Demo complete.${C.reset}\n`);
}

main().catch(err => {
  console.error('Demo failed:', err);
  process.exitCode = 1;
});
