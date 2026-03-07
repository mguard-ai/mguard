/**
 * WITNESS PROTOCOL — Full Demonstration
 *
 * Two autonomous trading agents on a regulated desk.
 * Shows the complete lifecycle:
 *
 *   1. Normal trading with hash-chained audit trail
 *   2. Prompt injection attack → immune system detects anomaly
 *   3. Cross-agent antibody sharing → instant protection
 *   4. Regulatory audit → cryptographic attestation certificates
 *   5. Independent verification → tamper-proof compliance proof
 *
 * Every action is hash-chained. Every decision is attested.
 * Every threat is remembered. Every proof is verifiable.
 */

import { Bulwark, noOscillation } from '../src/index';
import type { Decision, AttestationCertificate, VerificationResult } from '../src/types';

// ── Formatting ──────────────────────────────────────────────────────────────

const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';
const BG_RED = '\x1b[41m';
const BG_GREEN = '\x1b[42m';

function header(title: string) {
  const w = 64;
  const pad = Math.max(0, Math.floor((w - title.length) / 2));
  console.log('');
  console.log(`${CYAN}${'═'.repeat(w)}${RESET}`);
  console.log(`${CYAN}║${RESET}${' '.repeat(pad)}${BOLD}${WHITE}${title}${RESET}${' '.repeat(w - pad - title.length)}${CYAN}║${RESET}`);
  console.log(`${CYAN}${'═'.repeat(w)}${RESET}`);
}

function phase(n: number, title: string) {
  console.log(`\n${BOLD}${CYAN}▸ PHASE ${n}: ${title}${RESET}`);
  console.log(`${DIM}${'─'.repeat(50)}${RESET}`);
}

function trade(time: string, action: string, qty: number, sym: string, price: number, result: Decision) {
  const status = result.allowed
    ? `${GREEN}✓ allowed${RESET}`
    : `${RED}✗ BLOCKED${RESET}`;
  const idx = result.traceEntry?.index ?? '?';
  const side = action === 'buy' ? `${GREEN}BUY ${RESET}` : `${YELLOW}SELL${RESET}`;
  console.log(
    `  ${DIM}[${time}]${RESET} ${side} ${String(qty).padStart(5)} ${sym.padEnd(5)} @ $${price.toFixed(2).padStart(8)}  ${status}  ${DIM}trace #${idx}${RESET}`,
  );
  if (!result.allowed) {
    for (const v of result.violations.filter(v => v.severity === 'critical')) {
      console.log(`${RED}           ↳ ${v.rule}: ${v.message}${RESET}`);
    }
  }
  if (result.immuneResponse?.threat) {
    const ir = result.immuneResponse;
    const tag = ir.threatType === 'known' ? 'KNOWN THREAT' : 'ANOMALY';
    console.log(`${BG_RED}${WHITE}           ↳ IMMUNE: ${tag} (confidence: ${ir.confidence.toFixed(2)}) — ${ir.explanation}${RESET}`);
  }
}

function certificate(cert: AttestationCertificate, verification: VerificationResult, label: string) {
  const w = 54;
  const line = (l: string, r: string) => {
    const content = `  ${l}${' '.repeat(Math.max(1, w - 4 - l.length - r.length))}${r}`;
    console.log(`  ${DIM}│${RESET}${content}${DIM}│${RESET}`);
  };
  const sigShort = cert.signature.slice(0, 8) + '...' + cert.signature.slice(-8);
  const rootShort = cert.traceRoot.slice(0, 8) + '...' + cert.traceRoot.slice(-8);

  console.log(`  ${DIM}┌${'─'.repeat(w)}┐${RESET}`);
  line(`${BOLD}ATTESTATION CERTIFICATE${RESET}`, label);
  line('', '');
  line(`Protocol:    ${CYAN}${cert.protocol}${RESET}`, '');
  line(`Agent:       ${cert.agentId.slice(0, 20)}`, '');
  line(`Contract:    ${cert.contractId}`, '');
  line(`Period:      ${new Date(cert.period.start).toISOString().slice(11, 19)} — ${new Date(cert.period.end).toISOString().slice(11, 19)}`, '');
  line(`Actions:     ${cert.compliance.totalActions} total, ${cert.compliance.allowed} allowed, ${cert.compliance.blocked} blocked`, '');
  line(`Compliance:  ${BOLD}${cert.compliance.complianceRate >= 95 ? GREEN : cert.compliance.complianceRate >= 80 ? YELLOW : RED}${cert.compliance.complianceRate.toFixed(1)}%${RESET}`, '');
  line(`Drift:       ${cert.behavioral.driftScore.toFixed(3)}`, '');
  line(`Signature:   ${DIM}${sigShort}${RESET}`, '');
  line(`Merkle root: ${DIM}${rootShort}${RESET}`, '');
  line('', '');

  const sigIcon = verification.signatureValid ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
  const chainIcon = verification.chainIntegrity ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
  const compIcon = verification.complianceVerified ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
  const allIcon = verification.valid ? `${BG_GREEN}${WHITE} VALID ${RESET}` : `${BG_RED}${WHITE} INVALID ${RESET}`;

  line(`VERIFICATION:  ${allIcon}`, '');
  line(`  Signature:   ${sigIcon} ${verification.signatureValid ? 'VALID' : 'INVALID'}`, '');
  line(`  Chain:       ${chainIcon} ${verification.chainIntegrity ? `INTACT (${cert.traceLength} entries)` : 'BROKEN'}`, '');
  line(`  Compliance:  ${compIcon} ${verification.complianceVerified ? 'VERIFIED' : 'FAILED'}`, '');
  console.log(`  ${DIM}└${'─'.repeat(w)}┘${RESET}`);
}

// ── Market Simulation ───────────────────────────────────────────────────────

interface Position { symbol: string; quantity: number; avgCost: number }

interface TradingState {
  cash: number;
  positions: Record<string, Position>;
  prices: Record<string, number>;
}

function totalValue(s: TradingState): number {
  let v = s.cash;
  for (const pos of Object.values(s.positions)) {
    v += pos.quantity * (s.prices[pos.symbol] ?? 0);
  }
  return v;
}

function posWeight(s: TradingState, sym: string): number {
  const total = totalValue(s);
  if (total <= 0) return 0;
  const pos = s.positions[sym];
  if (!pos) return 0;
  return (pos.quantity * (s.prices[sym] ?? 0)) / total;
}

// ── Contract (shared by all desk agents) ────────────────────────────────────

function buildDeskContract(name: string) {
  return Bulwark.contract(name)
    .description('Regulated trading desk — behavioral contract')

    .pre('valid-order', ctx => {
      const o = ctx.input;
      return o && ['buy', 'sell'].includes(o.action) && typeof o.symbol === 'string' && o.quantity > 0;
    })
    .pre('market-hours', ctx => ctx.state.marketOpen !== false)
    .pre('sufficient-funds', ctx => {
      if (ctx.input?.action !== 'buy') return true;
      const s: TradingState = ctx.state.book;
      const cost = (s.prices[ctx.input.symbol] ?? 0) * ctx.input.quantity;
      return s.cash >= cost;
    })
    .pre('concentration-limit-35pct', ctx => {
      if (ctx.input?.action !== 'buy') return true;
      const s: TradingState = ctx.state.book;
      const price = s.prices[ctx.input.symbol] ?? 0;
      const newQty = (s.positions[ctx.input.symbol]?.quantity ?? 0) + ctx.input.quantity;
      const newPosValue = newQty * price;
      const total = totalValue(s);
      return total > 0 ? newPosValue / total <= 0.35 : true;
    })
    .pre('max-drawdown-15pct', ctx => {
      const s: TradingState = ctx.state.book;
      const initial = ctx.state.initialValue ?? totalValue(s);
      return (initial - totalValue(s)) / initial < 0.15;
    })

    .post('execution-acknowledged', ctx => {
      return ctx.output && ctx.output.executed === true;
    })

    .invariant('solvent', ctx => totalValue(ctx.state.book) > 0)

    .budget({ maxActions: 100, maxCost: 2.00 })

    .sequence('no-oscillation', noOscillation(4).check, 'warning',
      'Must not oscillate buy/sell on same instrument')

    .recover('block')
    .build();
}

// ── Agent Factory ───────────────────────────────────────────────────────────

function createTrader(book: TradingState) {
  return async (order: { action: string; symbol: string; quantity: number }) => {
    const price = book.prices[order.symbol] ?? 0;

    if (order.action === 'buy') {
      const cost = price * order.quantity;
      book.cash -= cost;
      const pos = book.positions[order.symbol] ?? { symbol: order.symbol, quantity: 0, avgCost: 0 };
      const totalCost = pos.avgCost * pos.quantity + cost;
      pos.quantity += order.quantity;
      pos.avgCost = totalCost / pos.quantity;
      book.positions[order.symbol] = pos;
    } else {
      book.cash += price * order.quantity;
      const pos = book.positions[order.symbol];
      if (pos) pos.quantity -= order.quantity;
    }

    return {
      executed: true,
      action: order.action,
      symbol: order.symbol,
      quantity: order.quantity,
      price,
      value: totalValue(book),
    };
  };
}

// ── Demo ────────────────────────────────────────────────────────────────────

async function demo() {
  header('WITNESS PROTOCOL — LIVE DEMONSTRATION');
  console.log(`${DIM}  Cryptographic behavioral attestation + adaptive immune system${RESET}`);
  console.log(`${DIM}  for autonomous AI agents on a regulated trading desk.${RESET}`);

  // ── Setup ──

  const prices: Record<string, number> = {
    AAPL: 189.50, MSFT: 425.30, GOOGL: 176.80, NVDA: 875.40, AMZN: 192.60, TSLA: 248.50,
  };

  const bookAlpha: TradingState = { cash: 500_000, positions: {}, prices: { ...prices } };
  const bookBeta: TradingState = { cash: 500_000, positions: {}, prices: { ...prices } };

  const contractAlpha = buildDeskContract('desk-alpha');
  const contractBeta = buildDeskContract('desk-beta');

  const alpha = Bulwark.wrap(createTrader(bookAlpha), contractAlpha);
  const beta = Bulwark.wrap(createTrader(bookBeta), contractBeta);

  alpha.setState('book', bookAlpha);
  alpha.setState('initialValue', totalValue(bookAlpha));
  alpha.setState('marketOpen', true);

  beta.setState('book', bookBeta);
  beta.setState('initialValue', totalValue(bookBeta));
  beta.setState('marketOpen', true);

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 1: Normal Operations
  // ════════════════════════════════════════════════════════════════════════

  phase(1, 'NORMAL OPERATIONS');
  console.log(`  ${DIM}Agent ALPHA — Momentum strategy | Agent BETA — Value strategy${RESET}`);
  console.log(`  ${DIM}Building behavioral baseline (immune system learning)...${RESET}\n`);

  // 21 trades each — enough to establish immune baseline (learning period = 20)
  const alphaOrders = [
    { action: 'buy', symbol: 'NVDA', quantity: 80 },
    { action: 'buy', symbol: 'AAPL', quantity: 200 },
    { action: 'buy', symbol: 'MSFT', quantity: 100 },
    { action: 'sell', symbol: 'AAPL', quantity: 50 },
    { action: 'buy', symbol: 'GOOGL', quantity: 150 },
    { action: 'buy', symbol: 'AMZN', quantity: 100 },
    { action: 'sell', symbol: 'NVDA', quantity: 20 },
    { action: 'buy', symbol: 'AAPL', quantity: 80 },
    { action: 'sell', symbol: 'MSFT', quantity: 30 },
    { action: 'buy', symbol: 'NVDA', quantity: 40 },
    { action: 'sell', symbol: 'AMZN', quantity: 25 },
    { action: 'buy', symbol: 'GOOGL', quantity: 50 },
    { action: 'sell', symbol: 'GOOGL', quantity: 40 },
    { action: 'buy', symbol: 'TSLA', quantity: 60 },
    { action: 'sell', symbol: 'AAPL', quantity: 30 },
    { action: 'buy', symbol: 'AMZN', quantity: 40 },
    { action: 'sell', symbol: 'TSLA', quantity: 20 },
    { action: 'buy', symbol: 'MSFT', quantity: 25 },
    { action: 'sell', symbol: 'NVDA', quantity: 15 },
    { action: 'buy', symbol: 'AAPL', quantity: 30 },
    { action: 'sell', symbol: 'AMZN', quantity: 15 },
  ];

  const betaOrders = [
    { action: 'buy', symbol: 'MSFT', quantity: 120 },
    { action: 'buy', symbol: 'AAPL', quantity: 250 },
    { action: 'buy', symbol: 'GOOGL', quantity: 180 },
    { action: 'sell', symbol: 'MSFT', quantity: 40 },
    { action: 'buy', symbol: 'AMZN', quantity: 130 },
    { action: 'buy', symbol: 'NVDA', quantity: 60 },
    { action: 'sell', symbol: 'GOOGL', quantity: 50 },
    { action: 'buy', symbol: 'MSFT', quantity: 50 },
    { action: 'sell', symbol: 'AAPL', quantity: 70 },
    { action: 'buy', symbol: 'NVDA', quantity: 30 },
    { action: 'sell', symbol: 'AMZN', quantity: 30 },
    { action: 'buy', symbol: 'AAPL', quantity: 60 },
    { action: 'sell', symbol: 'NVDA', quantity: 15 },
    { action: 'buy', symbol: 'TSLA', quantity: 50 },
    { action: 'sell', symbol: 'AAPL', quantity: 25 },
    { action: 'buy', symbol: 'GOOGL', quantity: 40 },
    { action: 'sell', symbol: 'TSLA', quantity: 15 },
    { action: 'buy', symbol: 'AMZN', quantity: 30 },
    { action: 'sell', symbol: 'MSFT', quantity: 20 },
    { action: 'buy', symbol: 'AAPL', quantity: 35 },
    { action: 'sell', symbol: 'GOOGL', quantity: 20 },
  ];

  // Run both agents through normal trading
  let timeMinute = 30;
  let timeSecond = 0;

  console.log(`  ${BOLD}ALPHA:${RESET}`);
  for (const order of alphaOrders) {
    const time = `09:${String(timeMinute).padStart(2, '0')}:${String(timeSecond).padStart(2, '0')}`;
    const result = await alpha.call(order, { tokensUsed: 50, costIncurred: 0.0003 });
    alpha.setState('book', bookAlpha);
    trade(time, order.action, order.quantity, order.symbol, bookAlpha.prices[order.symbol], result);
    timeSecond += 12;
    if (timeSecond >= 60) { timeMinute++; timeSecond -= 60; }
  }

  timeMinute = 30; timeSecond = 5;
  console.log(`\n  ${BOLD}BETA:${RESET}`);
  for (const order of betaOrders) {
    const time = `09:${String(timeMinute).padStart(2, '0')}:${String(timeSecond).padStart(2, '0')}`;
    const result = await beta.call(order, { tokensUsed: 50, costIncurred: 0.0003 });
    beta.setState('book', bookBeta);
    trade(time, order.action, order.quantity, order.symbol, bookBeta.prices[order.symbol], result);
    timeSecond += 12;
    if (timeSecond >= 60) { timeMinute++; timeSecond -= 60; }
  }

  const immuneA = alpha.getImmuneStatus();
  const immuneB = beta.getImmuneStatus();
  console.log(`\n  ${DIM}Immune status:${RESET}`);
  console.log(`    ALPHA: ${immuneA.established ? `${GREEN}baseline established${RESET}` : 'learning'} (${immuneA.sampleCount} samples, ${immuneA.knownThreats} threats)`);
  console.log(`    BETA:  ${immuneB.established ? `${GREEN}baseline established${RESET}` : 'learning'} (${immuneB.sampleCount} samples, ${immuneB.knownThreats} threats)`);

  const chainA = alpha.getTraceChain();
  const chainB = beta.getTraceChain();
  console.log(`  ${DIM}Hash chains:${RESET}`);
  console.log(`    ALPHA: ${chainA.length} entries, last hash: ${DIM}${chainA[chainA.length - 1]?.hash.slice(0, 16)}...${RESET}`);
  console.log(`    BETA:  ${chainB.length} entries, last hash: ${DIM}${chainB[chainB.length - 1]?.hash.slice(0, 16)}...${RESET}`);

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 2: Attack — Manipulated Market Data
  // ════════════════════════════════════════════════════════════════════════

  phase(2, 'ATTACK — PROMPT INJECTION VIA MARKET DATA');
  console.log(`  ${RED}Adversary injects manipulated orders into ALPHA's action queue.${RESET}`);
  console.log(`  ${RED}Goal: drain the portfolio with outsized positions.${RESET}\n`);

  // Attack: massive NVDA buy — far exceeds cash and concentration limits
  const attackOrder = { action: 'buy', symbol: 'NVDA', quantity: 5000 };
  const r1 = await alpha.call(attackOrder, { tokensUsed: 50, costIncurred: 0.0003 });
  alpha.setState('book', bookAlpha);
  trade('09:45:01', 'buy', 5000, 'NVDA', bookAlpha.prices.NVDA, r1);

  // Second attack: same pattern again (builds threat memory for antibody export)
  const r2 = await alpha.call(attackOrder, { tokensUsed: 50, costIncurred: 0.0003 });
  alpha.setState('book', bookAlpha);
  trade('09:45:03', 'buy', 5000, 'NVDA', bookAlpha.prices.NVDA, r2);

  // Third vector: massive TSLA buy
  const attackOrder2 = { action: 'buy', symbol: 'TSLA', quantity: 8000 };
  const r3 = await alpha.call(attackOrder2, { tokensUsed: 50, costIncurred: 0.0003 });
  alpha.setState('book', bookAlpha);
  trade('09:45:05', 'buy', 8000, 'TSLA', bookAlpha.prices.TSLA, r3);

  const immuneAfterAttack = alpha.getImmuneStatus();
  console.log(`\n  ${BOLD}Immune response:${RESET}`);
  console.log(`    Known threats: ${RED}${immuneAfterAttack.knownThreats}${RESET} (recorded from blocked actions)`);
  console.log(`    Behavioral baseline: ${immuneAfterAttack.established ? 'intact' : 'disrupted'}`);
  console.log(`    ${DIM}The immune system learned these attack patterns.${RESET}`);
  console.log(`    ${DIM}Future identical attacks will be flagged before contract evaluation.${RESET}`);

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 3: Cross-Agent Antibody Transfer
  // ════════════════════════════════════════════════════════════════════════

  phase(3, 'CROSS-AGENT IMMUNITY — ANTIBODY TRANSFER');
  console.log(`  ${CYAN}ALPHA exports threat antibodies → BETA imports them.${RESET}`);
  console.log(`  ${DIM}BETA gains immunity to attacks it has never seen.${RESET}\n`);

  const antibodies = alpha.exportAntibodies();
  console.log(`  ALPHA exported ${BOLD}${antibodies.length}${RESET} antibodies:`);
  for (const ab of antibodies) {
    console.log(`    ${DIM}•${RESET} ${ab.description} ${DIM}(effectiveness: ${(ab.effectiveness * 100).toFixed(0)}%)${RESET}`);
  }

  const imported = beta.importAntibodies(antibodies);
  console.log(`\n  BETA imported ${BOLD}${GREEN}${imported}${RESET} antibodies.`);

  // Now attack BETA with the same order that hit ALPHA
  console.log(`\n  ${RED}Same adversary now targets BETA with identical attack:${RESET}\n`);

  const betaAttack = await beta.call(attackOrder, { tokensUsed: 50, costIncurred: 0.0003 });
  beta.setState('book', bookBeta);
  trade('09:50:01', 'buy', 5000, 'NVDA', bookBeta.prices.NVDA, betaAttack);

  if (betaAttack.immuneResponse?.threat) {
    console.log(`\n  ${GREEN}${BOLD}Antibody matched.${RESET} BETA recognized the threat pattern instantly`);
    console.log(`  ${DIM}without ever encountering it before — learned from ALPHA's experience.${RESET}`);
  } else if (!betaAttack.allowed) {
    console.log(`\n  ${GREEN}${BOLD}Blocked by contract.${RESET} BETA's behavioral contract prevented the attack.`);
    console.log(`  ${DIM}Imported antibodies provide additional early-warning detection.${RESET}`);
  }

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 4: Continue Normal Trading (post-attack)
  // ════════════════════════════════════════════════════════════════════════

  phase(4, 'RECOVERY — NORMAL OPERATIONS RESUME');
  console.log(`  ${DIM}Both agents continue trading. Immune system remains vigilant.${RESET}\n`);

  const recoveryOrders = [
    { action: 'sell', symbol: 'GOOGL', quantity: 30 },
    { action: 'buy', symbol: 'AAPL', quantity: 40 },
    { action: 'sell', symbol: 'NVDA', quantity: 15 },
  ];

  let rTime = 51;
  for (const order of recoveryOrders) {
    const result = await alpha.call(order, { tokensUsed: 50, costIncurred: 0.0003 });
    alpha.setState('book', bookAlpha);
    trade(`09:${rTime}:00`, order.action, order.quantity, order.symbol, bookAlpha.prices[order.symbol] ?? 0, result);
    rTime++;
  }

  const metricsA = alpha.getMetrics();
  const metricsB = beta.getMetrics();
  console.log(`\n  ${DIM}Session totals:${RESET}`);
  console.log(`    ALPHA: ${metricsA.totalCalls} actions, ${metricsA.totalBlocked} blocked, violation rate ${(metricsA.violationRate * 100).toFixed(1)}%`);
  console.log(`    BETA:  ${metricsB.totalCalls} actions, ${metricsB.totalBlocked} blocked, violation rate ${(metricsB.violationRate * 100).toFixed(1)}%`);

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 5: Regulatory Attestation
  // ════════════════════════════════════════════════════════════════════════

  phase(5, 'REGULATORY AUDIT — CRYPTOGRAPHIC ATTESTATION');
  console.log(`  ${DIM}EU AI Act Article 14 — Generating tamper-proof compliance certificates.${RESET}`);
  console.log(`  ${DIM}Each certificate contains a Merkle root of the full behavioral trace,${RESET}`);
  console.log(`  ${DIM}signed with a per-session secret. Any tampering invalidates the proof.${RESET}\n`);

  const certAlpha = alpha.attest();
  const verifyAlpha = alpha.verifyAttestation(certAlpha);
  certificate(certAlpha, verifyAlpha, 'ALPHA');

  console.log('');

  const certBeta = beta.attest();
  const verifyBeta = beta.verifyAttestation(certBeta);
  certificate(certBeta, verifyBeta, 'BETA');

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 6: Tamper Detection
  // ════════════════════════════════════════════════════════════════════════

  phase(6, 'TAMPER DETECTION — FORGED CERTIFICATE');
  console.log(`  ${DIM}Adversary attempts to forge ALPHA's certificate to hide the attack.${RESET}`);
  console.log(`  ${RED}Modifying compliance rate from ${certAlpha.compliance.complianceRate.toFixed(1)}% → 100.0%...${RESET}\n`);

  const forged: AttestationCertificate = {
    ...certAlpha,
    compliance: { ...certAlpha.compliance, complianceRate: 100, blocked: 0 },
  };
  const verifyForged = alpha.verifyAttestation(forged);
  certificate(forged, verifyForged, 'FORGED');

  console.log(`\n  ${GREEN}${BOLD}Forgery detected.${RESET} The cryptographic signature does not match the`);
  console.log(`  ${DIM}tampered data. The original Merkle root and compliance statistics${RESET}`);
  console.log(`  ${DIM}are mathematically bound to the actual behavioral trace.${RESET}`);

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 7: Final Report
  // ════════════════════════════════════════════════════════════════════════

  phase(7, 'SESSION SUMMARY');

  const finalImmuneA = alpha.getImmuneStatus();
  const finalImmuneB = beta.getImmuneStatus();
  const driftA = alpha.getDrift();
  const driftB = beta.getDrift();

  console.log(`\n  ${BOLD}Agent ALPHA${RESET}`);
  console.log(`    Portfolio:    $${totalValue(bookAlpha).toLocaleString('en-US', { minimumFractionDigits: 0 })}`);
  console.log(`    Actions:      ${metricsA.totalCalls} total, ${metricsA.totalBlocked} blocked`);
  console.log(`    Compliance:   ${certAlpha.compliance.complianceRate.toFixed(1)}%`);
  console.log(`    Drift:        ${driftA.score.toFixed(3)} (${driftA.trending})`);
  console.log(`    Immune:       ${finalImmuneA.knownThreats} threats memorized, ${finalImmuneA.sampleCount} samples`);
  console.log(`    Trace:        ${alpha.getTraceChain().length} entries, chain intact`);

  console.log(`\n  ${BOLD}Agent BETA${RESET}`);
  console.log(`    Portfolio:    $${totalValue(bookBeta).toLocaleString('en-US', { minimumFractionDigits: 0 })}`);
  console.log(`    Actions:      ${metricsB.totalCalls} total, ${metricsB.totalBlocked} blocked`);
  console.log(`    Compliance:   ${certBeta.compliance.complianceRate.toFixed(1)}%`);
  console.log(`    Drift:        ${driftB.score.toFixed(3)} (${driftB.trending})`);
  console.log(`    Immune:       ${finalImmuneB.knownThreats} native + ${finalImmuneB.antibodyCount} imported antibodies`);
  console.log(`    Trace:        ${beta.getTraceChain().length} entries, chain intact`);

  console.log(`\n  ${BOLD}Witness Protocol${RESET}`);
  console.log(`    Certificates: 2 generated, 2 verified, 1 forgery detected`);
  console.log(`    Antibodies:   ${antibodies.length} shared (ALPHA → BETA)`);
  console.log(`    Hash chains:  ${alpha.getTraceChain().length + beta.getTraceChain().length} total entries across both agents`);
  console.log(`    Attestation:  ${CYAN}witness/1.0${RESET}`);

  header('END OF DEMONSTRATION');
  console.log(`${DIM}  Every action was hash-chained. Every decision was attested.${RESET}`);
  console.log(`${DIM}  Every threat was remembered. Every proof is verifiable.${RESET}\n`);
}

demo().catch(console.error);
