/**
 * Example: Trading Bot with Bulwark
 *
 * Demonstrates:
 * - State-dependent invariants (no negative balance, concentration limits)
 * - Multi-step sequence safety (no oscillation, no rapid trading)
 * - Structural unreachability (budget gates)
 * - Behavioral drift detection during market events
 * - Comprehensive audit for regulatory compliance
 */

import { Bulwark, noOscillation } from '../src/index';

// ── Portfolio State ────────────────────────────────────────────────────────

interface Portfolio {
  cash: number;
  positions: Record<string, number>;  // symbol → quantity
  prices: Record<string, number>;     // symbol → current price
}

interface Order {
  action: 'buy' | 'sell';
  symbol: string;
  quantity: number;
}

function portfolioValue(p: Portfolio): number {
  let total = p.cash;
  for (const [sym, qty] of Object.entries(p.positions)) {
    total += qty * (p.prices[sym] ?? 0);
  }
  return total;
}

function positionWeight(p: Portfolio, symbol: string): number {
  const total = portfolioValue(p);
  if (total <= 0) return 0;
  const posValue = (p.positions[symbol] ?? 0) * (p.prices[symbol] ?? 0);
  return posValue / total;
}

// ── Contract ───────────────────────────────────────────────────────────────

const contract = Bulwark.contract('trading-bot')
  .description('Safety harness for automated trading agent')

  // Preconditions
  .pre('valid-order', (ctx) => {
    const order: Order = ctx.input;
    return (
      order &&
      ['buy', 'sell'].includes(order.action) &&
      typeof order.symbol === 'string' &&
      order.quantity > 0
    );
  })
  .pre('market-open', (ctx) => {
    // Simulate market hours check
    return ctx.state.marketOpen !== false;
  })

  // Preconditions — structural gates checked BEFORE agent runs (unreachable states)
  .pre('sufficient-cash', (ctx) => {
    const portfolio: Portfolio = ctx.state.portfolio;
    const order: Order = ctx.input;
    if (order?.action !== 'buy') return true;
    const price = portfolio.prices[order.symbol] ?? 0;
    return portfolio.cash >= price * order.quantity;
  })
  .pre('max-concentration-40pct', (ctx) => {
    const portfolio: Portfolio = ctx.state.portfolio;
    const order: Order = ctx.input;
    if (order?.action !== 'buy') return true;
    const price = portfolio.prices[order.symbol] ?? 0;
    const newPosValue = ((portfolio.positions[order.symbol] ?? 0) + order.quantity) * price;
    const newTotal = portfolioValue(portfolio) + 0; // total doesn't change on buy, just cash→position
    return newTotal > 0 ? newPosValue / newTotal <= 0.40 : true;
  })
  .pre('max-drawdown-20pct', (ctx) => {
    const portfolio: Portfolio = ctx.state.portfolio;
    const initialValue = ctx.state.initialValue ?? portfolioValue(portfolio);
    const currentValue = portfolioValue(portfolio);
    const drawdown = (initialValue - currentValue) / initialValue;
    return drawdown < 0.20;
  })

  // Invariants
  .invariant('positive-portfolio', (ctx) => {
    const portfolio: Portfolio = ctx.state.portfolio;
    return portfolioValue(portfolio) > 0;
  })

  // Budget — max 50 trades per session, max $1 in API costs
  .budget({ maxActions: 50, maxCost: 1.00 })

  // Sequence rules
  .sequence('no-oscillation', noOscillation(4).check, 'warning',
    'Agent must not oscillate between buy/sell on the same stock')
  .sequence('max-trades-per-minute', (history) => {
    if (history.length < 10) return true;
    const last10 = history.slice(-10);
    const span = last10[last10.length - 1].timestamp - last10[0].timestamp;
    return span > 30000; // At least 30s for 10 trades
  }, 'warning', 'Trading too rapidly — possible runaway loop')

  .recover('block')
  .build();

// ── Simulated Trading Agent ────────────────────────────────────────────────

function createTradingAgent(portfolio: Portfolio) {
  return async (order: Order) => {
    const price = portfolio.prices[order.symbol] ?? 100;

    if (order.action === 'buy') {
      const cost = price * order.quantity;
      portfolio.cash -= cost;
      portfolio.positions[order.symbol] = (portfolio.positions[order.symbol] ?? 0) + order.quantity;
    } else {
      const revenue = price * order.quantity;
      portfolio.cash += revenue;
      portfolio.positions[order.symbol] = (portfolio.positions[order.symbol] ?? 0) - order.quantity;
    }

    return {
      executed: true,
      action: order.action,
      symbol: order.symbol,
      quantity: order.quantity,
      price,
      portfolioValue: portfolioValue(portfolio),
    };
  };
}

// ── Run Demo ───────────────────────────────────────────────────────────────

async function demo() {
  console.log('Trading Bot — Bulwark Demo\n');

  const portfolio: Portfolio = {
    cash: 100000,
    positions: {},
    prices: { AAPL: 185, GOOGL: 175, MSFT: 420, TSLA: 250, AMZN: 190 },
  };

  const tradingAgent = createTradingAgent(portfolio);
  const bot = Bulwark.wrap(tradingAgent, contract);
  bot.setState('portfolio', portfolio);
  bot.setState('initialValue', portfolioValue(portfolio));
  bot.setState('marketOpen', true);

  // ── Series of trades ──
  const orders: Order[] = [
    { action: 'buy', symbol: 'AAPL', quantity: 100 },   // $18,500 — OK
    { action: 'buy', symbol: 'GOOGL', quantity: 100 },   // $17,500 — OK
    { action: 'buy', symbol: 'MSFT', quantity: 50 },     // $21,000 — OK
    { action: 'buy', symbol: 'TSLA', quantity: 80 },     // $20,000 — OK
    { action: 'buy', symbol: 'AAPL', quantity: 500 },    // $92,500 — BLOCKED (concentration + negative cash)
    { action: 'sell', symbol: 'GOOGL', quantity: 50 },   // Sell half GOOGL — OK
    { action: 'buy', symbol: 'AMZN', quantity: 50 },     // $9,500 — OK
  ];

  for (const order of orders) {
    const result = await bot.call(order, { tokensUsed: 50, costIncurred: 0.0005 });
    const status = result.allowed ? 'EXEC' : 'BLOCKED';
    console.log(`[${status}] ${order.action.toUpperCase()} ${order.quantity} ${order.symbol}`);
    if (!result.allowed) {
      for (const v of result.violations.filter(v => v.severity === 'critical')) {
        console.log(`  reason: ${v.rule}`);
      }
    }
    // Update portfolio reference in state
    bot.setState('portfolio', portfolio);
  }

  // ── Market crash simulation ──
  console.log('\n── Market Crash ──');
  portfolio.prices = { AAPL: 120, GOOGL: 110, MSFT: 280, TSLA: 150, AMZN: 120 };
  bot.setState('portfolio', portfolio);
  console.log(`Portfolio value dropped to $${portfolioValue(portfolio).toFixed(0)}`);

  // Try to trade during crash
  const crashOrder = { action: 'buy' as const, symbol: 'TSLA', quantity: 100 };
  const crashResult = await bot.call(crashOrder, { tokensUsed: 50, costIncurred: 0.0005 });
  console.log(`[${crashResult.allowed ? 'EXEC' : 'BLOCKED'}] Buy 100 TSLA during crash`);
  if (!crashResult.allowed) {
    for (const v of crashResult.violations) {
      console.log(`  reason: ${v.rule} (${v.severity})`);
    }
  }

  // ── Results ──
  console.log('\n── Final State ──');
  console.log(`Cash: $${portfolio.cash.toFixed(0)}`);
  console.log(`Portfolio value: $${portfolioValue(portfolio).toFixed(0)}`);
  console.log(`Positions: ${JSON.stringify(portfolio.positions)}`);

  const m = bot.getMetrics();
  console.log(`\nTrades: ${m.totalCalls} total, ${m.totalBlocked} blocked`);
  console.log(`Violation rate: ${(m.violationRate * 100).toFixed(1)}%`);

  console.log('\n── Audit ──');
  const audit = bot.getAudit();
  console.log(audit.summary);
}

demo().catch(console.error);
