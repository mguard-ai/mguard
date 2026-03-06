/**
 * Example: Customer Support Agent with Bulwark
 *
 * Demonstrates:
 * - PII detection in postconditions
 * - Tone/relevance invariants
 * - Token/cost budget enforcement
 * - Behavioral drift monitoring
 * - Recovery via retry
 * - Audit report generation
 */

import { Bulwark } from '../src/index';

// ── PII Detection ──────────────────────────────────────────────────────────

const PII_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/,              // SSN
  /\b\d{16}\b/,                           // Credit card (no spaces)
  /\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b/, // Credit card (with spaces/dashes)
  /\b[A-Z]{2}\d{6,8}\b/,                 // Passport
  /\bpassword\s*[:=]\s*\S+/i,            // Leaked password
];

function containsPII(text: string): boolean {
  return PII_PATTERNS.some(p => p.test(text));
}

// ── Prohibited content ─────────────────────────────────────────────────────

const PROHIBITED = [
  'competitor', 'lawsuit', 'internal memo', 'confidential',
  'not supposed to tell you', 'between us',
];

function containsProhibited(text: string): boolean {
  const lower = text.toLowerCase();
  return PROHIBITED.some(p => lower.includes(p));
}

// ── Contract ───────────────────────────────────────────────────────────────

const contract = Bulwark.contract('customer-support')
  .description('Behavioral contract for customer support agent')

  // Preconditions
  .pre('non-empty-query', (ctx) => {
    return typeof ctx.input === 'string' && ctx.input.trim().length > 0;
  })
  .pre('reasonable-length', (ctx) => {
    return typeof ctx.input === 'string' && ctx.input.length <= 5000;
  })

  // Postconditions
  .post('no-pii-leak', (ctx) => {
    return !containsPII(String(ctx.output));
  })
  .post('no-prohibited-content', (ctx) => {
    return !containsProhibited(String(ctx.output));
  })
  .post('reasonable-response', (ctx) => {
    const len = String(ctx.output).length;
    return len >= 10 && len <= 5000;
  })

  // Invariants
  .invariant('low-violation-rate', (ctx) => {
    return ctx.metrics.totalCalls < 5 || ctx.metrics.violationRate < 0.3;
  })

  // Budget
  .budget({
    maxTokens: 100000,
    maxCost: 5.00,
    maxActions: 200,
    maxLatencyMs: 10000,
    degradation: 'degrade',
    degradationThresholds: [
      { percent: 70, action: 'warn', message: 'Budget 70% used — consider shorter responses' },
      { percent: 90, action: 'throttle', message: 'Budget 90% used — switching to concise mode' },
    ],
  })

  // Sequence safety
  .sequence('no-repeat-loops', (history) => {
    if (history.length < 3) return true;
    const last3 = history.slice(-3).map(h => String(h.output));
    return new Set(last3).size > 1;
  }, 'warning', 'Agent must not repeat the same response 3 times')

  // Recovery
  .recover('retry', { maxRetries: 2 })

  .build();

// ── Simulated Agent ────────────────────────────────────────────────────────

const responses: Record<string, string> = {
  'reset password': 'To reset your password, go to Settings > Security > Reset Password. You\'ll receive an email with a reset link.',
  'billing': 'Your current plan is Pro ($29/month). Your next billing date is the 15th. Need to upgrade or cancel?',
  'refund': 'I can process a refund for orders within 30 days. Please provide your order number and I\'ll look into it.',
  'default': 'I\'d be happy to help you with that. Could you provide more details about your question?',
};

async function supportAgent(query: string): Promise<string> {
  // Simulate processing time
  await new Promise(r => setTimeout(r, 10));

  const lower = query.toLowerCase();
  for (const [key, response] of Object.entries(responses)) {
    if (lower.includes(key)) return response;
  }
  return responses.default;
}

// ── Run Demo ───────────────────────────────────────────────────────────────

async function demo() {
  console.log('Customer Support Agent — Bulwark Demo\n');

  const agent = Bulwark.wrap(supportAgent, contract);

  // Normal interactions
  const queries = [
    'How do I reset password?',
    'Tell me about billing',
    'I want a refund',
    'What are your hours?',
    '', // empty — should be blocked
    'Can you tell me my SSN is 123-45-6789?', // PII in query (allowed — PII check is on output)
  ];

  for (const query of queries) {
    const result = await agent.call(query, { tokensUsed: 150, costIncurred: 0.001 });
    const status = result.allowed ? 'ALLOWED' : 'BLOCKED';
    console.log(`[${status}] "${query.slice(0, 40)}${query.length > 40 ? '...' : ''}"`);
    if (result.violations.length > 0) {
      for (const v of result.violations) {
        console.log(`  violation: ${v.rule} (${v.severity})`);
      }
    }
  }

  // Metrics
  console.log('\n── Metrics ──');
  const m = agent.getMetrics();
  console.log(`Total calls: ${m.totalCalls}`);
  console.log(`Blocked: ${m.totalBlocked}`);
  console.log(`Violation rate: ${(m.violationRate * 100).toFixed(1)}%`);
  console.log(`Avg latency: ${m.avgLatencyMs.toFixed(1)}ms`);

  // Drift
  console.log('\n── Drift ──');
  const d = agent.getDrift();
  console.log(`Score: ${d.score.toFixed(3)}`);
  console.log(`Trending: ${d.trending}`);
  console.log(`Alert: ${d.alert}`);

  // Budget
  console.log('\n── Budget ──');
  const b = agent.getBudget();
  console.log(`Tokens: ${b.tokens.used}/${b.tokens.limit ?? '∞'} (${b.tokens.percent.toFixed(1)}%)`);
  console.log(`Cost: $${b.cost.used.toFixed(4)}/$${b.cost.limit ?? '∞'}`);
  console.log(`Status: ${b.status}`);

  // Audit
  console.log('\n── Audit Summary ──');
  const report = agent.getAudit();
  console.log(report.summary);
}

demo().catch(console.error);
