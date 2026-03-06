import { AgentFn, AgentResult } from '../types';

export interface VercelAIAdapterOptions {
  systemPrompt?: string;
  costPerInputToken?: number;
  costPerOutputToken?: number;
}

/**
 * Creates an agent function from a Vercel AI SDK model.
 * Works with `generateText` from the `ai` package.
 *
 * @param model - Vercel AI SDK model (from `openai('gpt-4o')`, `anthropic('claude-sonnet-4-6')`, etc.)
 * @param opts - Generation options
 * @returns Agent function compatible with `Bulwark.wrap()`
 *
 * @example
 * ```typescript
 * import { openai } from '@ai-sdk/openai';
 * import { Bulwark } from 'bulwark';
 * import { vercelAI } from 'bulwark/adapters';
 *
 * const agent = vercelAI(openai('gpt-4o'), { systemPrompt: 'Be helpful.' });
 * const safe = Bulwark.wrap(agent, contract);
 * const result = await safe.call('Hello');
 * ```
 */
export function vercelAI(model: any, opts: VercelAIAdapterOptions = {}): AgentFn {
  return async (input: any): Promise<AgentResult> => {
    // Import dynamically to avoid hard dependency
    let generateText: any;
    try {
      const mod = await (Function('return import("ai")')() as Promise<any>);
      generateText = mod.generateText;
    } catch {
      throw new Error('Vercel AI SDK (ai) is required. Install it: npm install ai');
    }

    const prompt = typeof input === 'string' ? input : JSON.stringify(input);

    const result = await generateText({
      model,
      system: opts.systemPrompt,
      prompt,
    });

    const inputTokens = result.usage?.promptTokens ?? 0;
    const outputTokens = result.usage?.completionTokens ?? 0;
    const totalTokens = inputTokens + outputTokens;

    let cost: number | undefined;
    if (opts.costPerInputToken && opts.costPerOutputToken) {
      cost = inputTokens * opts.costPerInputToken + outputTokens * opts.costPerOutputToken;
    }

    return {
      __bulwark: true,
      output: result.text,
      tokensUsed: totalTokens,
      costIncurred: cost,
    };
  };
}
