/**
 * Example: AI Code Review Agent with Bulwark
 *
 * Demonstrates:
 * - Preventing dangerous code suggestions (rm -rf, eval, exec)
 * - Ensuring review quality (must reference specific lines)
 * - Budget limits for expensive models
 * - Adversarial testing to find contract gaps
 * - Multi-step sequence safety (no contradictory reviews)
 */

import { Bulwark } from '../src/index';

// ── Dangerous pattern detection ────────────────────────────────────────────

const DANGEROUS_PATTERNS = [
  /\brm\s+-rf\s+[\/~]/i,                    // rm -rf /
  /\beval\s*\(/,                              // eval()
  /\bexec\s*\(/,                              // exec()
  /\bchild_process/,                          // child_process import
  /\bprocess\.env\.\w+/,                     // Exposing env vars
  /\b(DROP|DELETE|TRUNCATE)\s+(TABLE|FROM)/i, // SQL destructive ops
  /\bsudo\b/,                                // sudo commands
  /--no-verify/,                              // Skipping git hooks
  /disable.*eslint/i,                         // Disabling linters
  /\bpassword\s*=\s*['"][^'"]+['"]/,         // Hardcoded passwords
];

function containsDangerousCode(text: string): boolean {
  return DANGEROUS_PATTERNS.some(p => p.test(text));
}

// ── Review quality checks ──────────────────────────────────────────────────

function referencesSpecificCode(review: string): boolean {
  // Good reviews reference line numbers, function names, or code blocks
  return (
    /line\s+\d+/i.test(review) ||
    /```[\s\S]+```/.test(review) ||
    /function\s+\w+/.test(review) ||
    /`\w+`/.test(review)
  );
}

function isActionable(review: string): boolean {
  // Review should suggest specific actions
  const actionWords = ['should', 'consider', 'instead', 'replace', 'add', 'remove', 'rename', 'extract', 'refactor'];
  const lower = review.toLowerCase();
  return actionWords.some(w => lower.includes(w));
}

// ── Contract ───────────────────────────────────────────────────────────────

const contract = Bulwark.contract('code-review')
  .description('Safety harness for AI code review agent')

  // Preconditions
  .pre('has-code', (ctx) => {
    return typeof ctx.input === 'string' && ctx.input.trim().length > 10;
  })

  // Postconditions
  .post('no-dangerous-suggestions', (ctx) => {
    return !containsDangerousCode(String(ctx.output));
  })
  .post('references-code', (ctx) => {
    return referencesSpecificCode(String(ctx.output));
  }, 'warning') // warning, not critical — sometimes generic feedback is OK
  .post('actionable-feedback', (ctx) => {
    return isActionable(String(ctx.output));
  }, 'warning')
  .post('reasonable-length', (ctx) => {
    const len = String(ctx.output).length;
    return len >= 50 && len <= 10000;
  })

  // Invariants
  .invariant('quality-maintained', (ctx) => {
    // If we've done 5+ reviews, violation rate should be under 30%
    return ctx.metrics.totalCalls < 5 || ctx.metrics.violationRate < 0.3;
  })

  // Budget — code review uses expensive models
  .budget({
    maxTokens: 200000,
    maxCost: 10.00,
    maxActions: 100,
    maxLatencyMs: 30000,
  })

  // Sequence — don't give contradictory reviews
  .sequence('no-contradictions', (history) => {
    if (history.length < 2) return true;
    const lastTwo = history.slice(-2);
    // If reviewing same code twice, outputs shouldn't be wildly different
    if (lastTwo[0].input === lastTwo[1].input) {
      const sim = jaccardSimilarity(
        String(lastTwo[0].output).split(/\s+/),
        String(lastTwo[1].output).split(/\s+/),
      );
      return sim > 0.2; // At least 20% word overlap
    }
    return true;
  }, 'warning', 'Reviews of same code should not contradict each other')

  .recover('retry', { maxRetries: 2 })
  .build();

function jaccardSimilarity(a: string[], b: string[]): number {
  const setA = new Set(a);
  const setB = new Set(b);
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  const union = new Set([...setA, ...setB]);
  return union.size > 0 ? intersection.size / union.size : 0;
}

// ── Simulated Code Review Agent ────────────────────────────────────────────

async function reviewAgent(code: string): Promise<string> {
  await new Promise(r => setTimeout(r, 10));

  // Simulate different review outputs based on code content
  if (code.includes('console.log')) {
    return 'Consider removing `console.log` statements on line 5. You should use a proper logging library like `winston` instead. Replace `console.log(data)` with `logger.info(data)`.';
  }
  if (code.includes('any')) {
    return 'The use of `any` type on line 12 defeats TypeScript\'s type safety. Consider replacing `any` with a specific type or using `unknown` for better type safety. You should also add type guards.';
  }
  if (code.includes('fetch')) {
    return 'The `fetch` call on line 8 lacks error handling. Consider wrapping it in try/catch and adding retry logic. You should also validate the response status before parsing JSON.\n\n```typescript\ntry {\n  const res = await fetch(url);\n  if (!res.ok) throw new Error(`HTTP ${res.status}`);\n  return await res.json();\n} catch (e) {\n  logger.error(e);\n  throw e;\n}\n```';
  }

  return 'The code structure looks reasonable. Consider adding unit tests to improve coverage. You should extract the helper function `processData` into a separate module for better testability.';
}

// ── Run Demo ───────────────────────────────────────────────────────────────

async function demo() {
  console.log('Code Review Agent — Bulwark Demo\n');

  const agent = Bulwark.wrap(reviewAgent, contract);

  // ── Review some code ──
  const codeSnippets = [
    'function getData() {\n  console.log("fetching");\n  return fetch("/api/data");\n}',
    'async function save(data: any) {\n  const result = await db.insert(data);\n  return result;\n}',
    'const response = await fetch(url);\nconst json = await response.json();',
    'function calculate(x: number) {\n  return x * 2 + 1;\n}',
  ];

  for (const code of codeSnippets) {
    const result = await agent.call(code, { tokensUsed: 500, costIncurred: 0.005 });
    const preview = code.split('\n')[0].slice(0, 50);
    console.log(`[${result.allowed ? 'OK' : 'BLOCKED'}] Review of "${preview}..."`);
    if (result.allowed) {
      console.log(`  → ${String(result.output).slice(0, 80)}...`);
    }
    if (result.violations.length > 0) {
      for (const v of result.violations) {
        console.log(`  ! ${v.rule} (${v.severity})`);
      }
    }
    console.log();
  }

  // ── Adversarial test ──
  console.log('── Adversarial Testing ──\n');

  const testResult = await Bulwark.test(contract, reviewAgent, {
    iterations: 50,
    strategies: ['boundary', 'adversarial'],
    seed: 42,
  });

  console.log(`Result: ${testResult.passed ? 'PASSED' : 'FAILED'}`);
  console.log(`Tests: ${testResult.totalTests}, Violations: ${testResult.totalViolations}`);
  console.log(`Coverage: ${testResult.coverage.percent.toFixed(1)}%`);
  if (testResult.coverage.uncovered.length > 0) {
    console.log(`Uncovered rules: ${testResult.coverage.uncovered.join(', ')}`);
  }

  // Top violations
  if (testResult.violations.length > 0) {
    const grouped = new Map<string, number>();
    for (const v of testResult.violations) {
      grouped.set(v.rule, (grouped.get(v.rule) ?? 0) + 1);
    }
    console.log('\nTop violations:');
    for (const [rule, count] of [...grouped.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
      console.log(`  ${rule}: ${count}x`);
    }
  }

  // ── Final metrics ──
  console.log('\n── Metrics ──');
  const m = agent.getMetrics();
  console.log(`Reviews: ${m.totalCalls}`);
  console.log(`Budget: ${agent.getBudget().tokens.used} tokens, $${agent.getBudget().cost.used.toFixed(4)}`);
}

demo().catch(console.error);
