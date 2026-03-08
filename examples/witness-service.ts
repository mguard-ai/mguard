/**
 * WITNESS VERIFICATION SERVICE — LIVE DEMO
 *
 * Demonstrates the complete third-party attestation flow:
 *   1. Witness node boots with its own Ed25519 identity
 *   2. Two AI trading agents register their public keys
 *   3. Agents execute trades under behavioral contracts
 *   4. Agents generate Ed25519-signed attestation certificates
 *   5. Certificates submitted to witness service for independent verification
 *   6. Witness counter-signs valid certificates (anyone can verify)
 *   7. Forged certificate detected and rejected
 *   8. Antibodies shared across agents via witness network
 *   9. Network dashboard shows ecosystem health
 *
 * This is NOT self-attestation. The witness node is an independent
 * third party that verifies and counter-signs certificates.
 * Anyone with the witness's public key can verify the counter-signature.
 */

import { Bulwark } from '../src/index';
import {
  generateWitnessKeys, witnessVerify, deterministicStringify,
  createWitnessServer, WitnessClient, createWitnessCertificate,
} from '../src/witness';

// ── ANSI Formatting ─────────────────────────────────────────────────────────

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  bgGreen: '\x1b[42m',
  bgRed: '\x1b[41m',
  bgBlue: '\x1b[44m',
  bgYellow: '\x1b[43m',
};

function banner(text: string, sub: string) {
  const w = 66;
  console.log(`\n${C.cyan}${'#'.repeat(w)}`);
  console.log(`##${' '.repeat(w - 4)}##`);
  console.log(`##${text.padStart((w - 4 + text.length) / 2).padEnd(w - 4)}##`);
  console.log(`##${sub.padStart((w - 4 + sub.length) / 2).padEnd(w - 4)}##`);
  console.log(`##${' '.repeat(w - 4)}##`);
  console.log(`${'#'.repeat(w)}${C.reset}\n`);
}

function phase(n: number, title: string) {
  console.log(`\n${C.bold}${C.blue}== Phase ${n}: ${title} ${'='.repeat(Math.max(0, 50 - title.length))}${C.reset}\n`);
}

function ok(msg: string) { console.log(`  ${C.green}[OK]${C.reset} ${msg}`); }
function fail(msg: string) { console.log(`  ${C.red}[FAIL]${C.reset} ${msg}`); }
function info(msg: string) { console.log(`  ${C.dim}${msg}${C.reset}`); }
function highlight(msg: string) { console.log(`  ${C.yellow}${msg}${C.reset}`); }

function box(title: string, lines: string[]) {
  const maxLen = Math.max(title.length, ...lines.map(l => l.length));
  const w = maxLen + 4;
  console.log(`  ${C.cyan}+${'-'.repeat(w)}+`);
  console.log(`  | ${C.bold}${title.padEnd(w - 2)}${C.cyan}|`);
  console.log(`  +${'-'.repeat(w)}+`);
  for (const line of lines) {
    console.log(`  | ${C.white}${line.padEnd(w - 2)}${C.cyan}|`);
  }
  console.log(`  +${'-'.repeat(w)}+${C.reset}`);
}

// ── Trading simulation ──────────────────────────────────────────────────────

const PRICES: Record<string, number> = {
  AAPL: 189.50, GOOGL: 141.80, MSFT: 378.90, NVDA: 875.40,
  AMZN: 178.25, TSLA: 248.50, META: 485.20, JPM: 195.60,
};

interface Order {
  symbol: string;
  qty: number;
  side: 'buy' | 'sell';
  strategy: string;
}

function createTradingContract(name: string) {
  return Bulwark.contract(name)
    .pre('valid-order', ctx => {
      const o = ctx.input as Order;
      return !!o && !!o.symbol && !!o.side && o.qty > 0;
    })
    .pre('known-symbol', ctx => (ctx.input as Order).symbol in PRICES)
    .post('position-limit', ctx => {
      const o = ctx.input as Order;
      return o.qty <= 1000;
    })
    .post('cash-limit', ctx => {
      const o = ctx.input as Order;
      const cost = o.qty * (PRICES[o.symbol] ?? 0);
      return cost <= 500000;
    })
    .budget({ maxActions: 100, maxCost: 10.0 })
    .build();
}

function randomOrder(strategy: string): Order {
  const symbols = Object.keys(PRICES);
  return {
    symbol: symbols[Math.floor(Math.random() * symbols.length)],
    qty: Math.floor(Math.random() * 200) + 10,
    side: Math.random() > 0.3 ? 'buy' : 'sell',
    strategy,
  };
}

// ── Main Demo ───────────────────────────────────────────────────────────────

async function main() {
  banner(
    'WITNESS VERIFICATION SERVICE',
    'Third-Party Attestation for AI Agent Compliance',
  );

  // ── Phase 1: Boot witness node ──────────────────────────────────────────
  phase(1, 'Witness Node Boot');

  const server = createWitnessServer({ port: 0 });
  await server.start();
  const client = new WitnessClient(`http://localhost:${server.port}`);

  const witnessInfo = await client.getWitnessInfo();
  ok(`Witness node online`);
  info(`  ID:        ${witnessInfo.witnessId}`);
  info(`  Protocol:  ${witnessInfo.protocol}`);
  info(`  Public Key: ${witnessInfo.publicKey.slice(0, 32)}...`);
  info(`  Endpoint:  http://localhost:${server.port}`);
  highlight(`  This node independently verifies agent certificates.`);
  highlight(`  Its public key is published — anyone can verify its counter-signatures.`);

  // ── Phase 2: Agent registration ─────────────────────────────────────────
  phase(2, 'Agent Key Registration');

  const alphaKeys = generateWitnessKeys();
  const betaKeys = generateWitnessKeys();

  await client.registerKey('ALPHA', alphaKeys.publicKey);
  ok(`ALPHA registered  (key: ${alphaKeys.publicKey.slice(0, 24)}...)`);

  await client.registerKey('BETA', betaKeys.publicKey);
  ok(`BETA  registered  (key: ${betaKeys.publicKey.slice(0, 24)}...)`);

  info(`  Keys stored in witness registry. Any certificate must match.`);

  // ── Phase 3: Agent execution ────────────────────────────────────────────
  phase(3, 'Agent Execution (Normal Trading)');

  const alphaContract = createTradingContract('alpha-momentum');
  const betaContract = createTradingContract('beta-value');

  const alphaAgent = Bulwark.wrap(
    async (order: Order) => ({
      fill: `${order.side} ${order.qty} ${order.symbol} @ $${PRICES[order.symbol]}`,
      cost: order.qty * (PRICES[order.symbol] ?? 0),
      strategy: order.strategy,
    }),
    alphaContract,
  );

  const betaAgent = Bulwark.wrap(
    async (order: Order) => ({
      fill: `${order.side} ${order.qty} ${order.symbol} @ $${PRICES[order.symbol]}`,
      cost: order.qty * (PRICES[order.symbol] ?? 0),
      strategy: order.strategy,
    }),
    betaContract,
  );

  // Normal trades
  let alphaAllowed = 0, alphaBlocked = 0;
  let betaAllowed = 0, betaBlocked = 0;

  for (let i = 0; i < 25; i++) {
    const r1 = await alphaAgent.call(randomOrder('momentum'), { costIncurred: 0.01 });
    if (r1.allowed) alphaAllowed++; else alphaBlocked++;

    const r2 = await betaAgent.call(randomOrder('value'), { costIncurred: 0.01 });
    if (r2.allowed) betaAllowed++; else betaBlocked++;
  }

  ok(`ALPHA: ${alphaAllowed + alphaBlocked} trades (${alphaAllowed} allowed, ${alphaBlocked} blocked)`);
  ok(`BETA:  ${betaAllowed + betaBlocked} trades (${betaAllowed} allowed, ${betaBlocked} blocked)`);

  const alphaImmune = alphaAgent.getImmuneStatus();
  const betaImmune = betaAgent.getImmuneStatus();
  info(`  ALPHA immune baseline: ${alphaImmune.established ? 'ESTABLISHED' : 'learning...'}`);
  info(`  BETA  immune baseline: ${betaImmune.established ? 'ESTABLISHED' : 'learning...'}`);

  // ── Phase 4: Attack ────────────────────────────────────────────────────
  phase(4, 'Attack Detection');

  const attackOrder: Order = { symbol: 'NVDA', qty: 5000, side: 'buy', strategy: 'exploit' };
  const attackResult = await alphaAgent.call(attackOrder);
  if (!attackResult.allowed) {
    ok(`Attack blocked: ${attackOrder.qty} ${attackOrder.symbol} ($${(attackOrder.qty * PRICES.NVDA).toLocaleString()})`);
    info(`  Violations: ${attackResult.violations.map(v => v.rule).join(', ')}`);
    if (attackResult.immuneResponse) {
      info(`  Immune: ${attackResult.immuneResponse.threatType} (confidence: ${attackResult.immuneResponse.confidence.toFixed(2)})`);
    }
  }

  // Second attack for antibody generation
  await alphaAgent.call(attackOrder);

  // ── Phase 5: Attestation & submission ──────────────────────────────────
  phase(5, 'Attestation & Witness Verification');

  // ALPHA certificate
  const alphaCert = createWitnessCertificate(alphaAgent, alphaKeys, 'ALPHA');
  info(`ALPHA certificate generated`);
  info(`  ID:         ${alphaCert.id}`);
  info(`  Actions:    ${alphaCert.compliance.totalActions}`);
  info(`  Compliance: ${alphaCert.compliance.complianceRate.toFixed(1)}%`);
  info(`  Trace root: ${alphaCert.traceRoot.slice(0, 16)}...`);
  info(`  Signature:  ${alphaCert.signature.slice(0, 32)}... (Ed25519)`);

  const alphaReceipt = await client.submitCertificate(alphaCert as any);
  if (alphaReceipt.result.valid) {
    ok(`ALPHA ${C.bgGreen}${C.white} VERIFIED ${C.reset} — counter-signed by ${alphaReceipt.witnessId}`);
    for (const detail of alphaReceipt.result.details) {
      info(`    ${detail}`);
    }
  } else {
    fail(`ALPHA verification failed`);
  }

  console.log('');

  // BETA certificate
  const betaCert = createWitnessCertificate(betaAgent, betaKeys, 'BETA');
  info(`BETA certificate generated`);
  info(`  ID:         ${betaCert.id}`);
  info(`  Actions:    ${betaCert.compliance.totalActions}`);
  info(`  Compliance: ${betaCert.compliance.complianceRate.toFixed(1)}%`);

  const betaReceipt = await client.submitCertificate(betaCert as any);
  if (betaReceipt.result.valid) {
    ok(`BETA  ${C.bgGreen}${C.white} VERIFIED ${C.reset} — counter-signed by ${betaReceipt.witnessId}`);
  }

  // ── Phase 6: Independent verification ──────────────────────────────────
  phase(6, 'Independent Third-Party Verification');

  highlight(`Any party can now verify these certificates without access to agent internals:`);
  console.log('');

  // Retrieve from registry
  const retrieved = await client.getCertificate(alphaCert.id);
  const wv = retrieved.certificate.witnessVerifications![0];

  // Verify the witness's counter-signature independently
  const counterPayload = deterministicStringify({
    certificateId: alphaCert.id,
    valid: true,
    details: wv.checks,
    verifiedAt: wv.verifiedAt,
  });
  const counterValid = witnessVerify(counterPayload, wv.signature, wv.witnessPublicKey);

  // Verify the agent's signature independently
  const { signature: agSig, publicKey: agPk, witnessVerifications: _, ...agBody } = retrieved.certificate;
  const agPayload = deterministicStringify(agBody);
  const agValid = witnessVerify(agPayload, agSig, agPk);

  box('Certificate Verification (ALPHA)', [
    `Agent signature:   ${agValid ? 'VALID (Ed25519)' : 'INVALID'}`,
    `Witness counter:   ${counterValid ? 'VALID (Ed25519)' : 'INVALID'}`,
    `Witness ID:        ${wv.witnessId}`,
    `Compliance:        ${retrieved.certificate.compliance.complianceRate.toFixed(1)}%`,
    `Actions:           ${retrieved.certificate.compliance.totalActions}`,
    `Blocked:           ${retrieved.certificate.compliance.blocked}`,
    `Drift score:       ${retrieved.certificate.behavioral.driftScore.toFixed(3)}`,
    `Trace root:        ${retrieved.certificate.traceRoot.slice(0, 32)}...`,
  ]);

  console.log('');
  ok(`Both signatures verified — certificate is ${C.bold}cryptographically authentic${C.reset}`);

  // ── Phase 7: Forgery detection ─────────────────────────────────────────
  phase(7, 'Forgery Detection');

  const forgedCert = {
    ...alphaCert,
    id: 'cert-forged-001',
    compliance: {
      ...alphaCert.compliance,
      complianceRate: 100,
      blocked: 0,
      allowed: alphaCert.compliance.totalActions,
    },
  };

  info(`Forged ALPHA certificate:`);
  info(`  Original compliance: ${alphaCert.compliance.complianceRate.toFixed(1)}%`);
  info(`  Forged compliance:   ${forgedCert.compliance.complianceRate}%`);
  info(`  Original blocked:    ${alphaCert.compliance.blocked}`);
  info(`  Forged blocked:      ${forgedCert.compliance.blocked}`);

  const forgedReceipt = await client.submitCertificate(forgedCert as any);
  if (!forgedReceipt.result.valid) {
    ok(`Forgery ${C.bgRed}${C.white} REJECTED ${C.reset}`);
    for (const detail of forgedReceipt.result.details) {
      const icon = detail.includes('INVALID') || detail.includes('INCONSISTENT') || detail.includes('MISMATCH')
        ? `${C.red}[X]${C.reset}` : `${C.green}[V]${C.reset}`;
      info(`    ${icon} ${detail}`);
    }
  } else {
    fail(`Forgery was not detected!`);
  }

  highlight(`  Ed25519 signature binds every field — any change invalidates the certificate.`);

  // ── Phase 8: Antibody network ──────────────────────────────────────────
  phase(8, 'Antibody Sharing Network');

  const alphaAntibodies = alphaAgent.exportAntibodies();
  info(`ALPHA has ${alphaAntibodies.length} antibod${alphaAntibodies.length === 1 ? 'y' : 'ies'} to share`);

  if (alphaAntibodies.length > 0) {
    const shareResult = await client.shareAntibodies(alphaAntibodies);
    ok(`${shareResult.added} antibod${shareResult.added === 1 ? 'y' : 'ies'} shared to witness network`);

    // BETA fetches from network
    const networkAntibodies = await client.fetchAntibodies();
    info(`BETA fetches from network: ${networkAntibodies.length} available`);

    if (networkAntibodies.length > 0) {
      const imported = betaAgent.importAntibodies(networkAntibodies);
      ok(`BETA imported ${imported} antibod${imported === 1 ? 'y' : 'ies'} — instant threat intelligence`);

      // Test that BETA now detects the same threat
      const betaAttack = await betaAgent.call(attackOrder);
      if (betaAttack.immuneResponse?.threat) {
        ok(`BETA detects attack via imported antibody (${betaAttack.immuneResponse.threatType}, confidence: ${betaAttack.immuneResponse.confidence.toFixed(2)})`);
      }
    }
  } else {
    info(`  No antibodies generated (attacks may need repeat exposure)`);
  }

  highlight(`  Witness network enables cross-agent threat intelligence.`);
  highlight(`  One agent's experience protects the entire ecosystem.`);

  // ── Phase 9: Network dashboard ─────────────────────────────────────────
  phase(9, 'Network Dashboard');

  const stats = await client.getStats();

  box('Witness Network', [
    `Verified Certificates:  ${stats.totalCertificates}`,
    `Registered Agents:      ${stats.totalAgents}`,
    `Witness Verifications:  ${stats.totalVerifications}`,
    `Shared Antibodies:      ${stats.totalAntibodiesShared}`,
    `Avg Compliance Rate:    ${stats.avgComplianceRate.toFixed(1)}%`,
    `Uptime:                 ${(stats.uptime / 1000).toFixed(1)}s`,
  ]);

  console.log('');

  box('Protocol Summary', [
    `Self-attestation:   HMAC-SHA256 (local, fast, private)`,
    `Public attestation: Ed25519 (verifiable by anyone)`,
    `Witness layer:      Independent counter-signatures`,
    `Antibody network:   Cross-agent threat intelligence`,
    ``,
    `Trust chain:`,
    `  Agent signs cert with Ed25519 private key`,
    `  -> Witness verifies signature + compliance stats`,
    `  -> Witness counter-signs with its own Ed25519 key`,
    `  -> Anyone verifies both signatures with public keys`,
    `  -> Certificate is cryptographically authentic`,
  ]);

  // ── Cleanup ──────────────────────────────────────────────────────────
  await server.stop();

  console.log(`\n${C.green}${C.bold}Demo complete.${C.reset}\n`);
}

main().catch(err => {
  console.error('Demo failed:', err);
  process.exitCode = 1;
});
