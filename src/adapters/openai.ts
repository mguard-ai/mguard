import { AgentFn, AgentResult } from '../types';

// Pricing per 1M tokens (input/output)
const PRICING: Record<string, { input: number; output: number }> = {
  'gpt-4o': { input: 2.50, output: 10.00 },
  'gpt-4o-mini': { input: 0.15, output: 0.60 },
  'gpt-4.1': { input: 2.00, output: 8.00 },
  'gpt-4.1-mini': { input: 0.40, output: 1.60 },
  'gpt-4.1-nano': { input: 0.10, output: 0.40 },
  'o1': { input: 15.00, output: 60.00 },
  'o1-mini': { input: 1.10, output: 4.40 },
  'o1-pro': { input: 150.00, output: 600.00 },
  'o3': { input: 10.00, output: 40.00 },
  'o3-mini': { input: 1.10, output: 4.40 },
  'o4-mini': { input: 1.10, output: 4.40 },
};

export interface OpenAIAdapterOptions {
  model?: string;
  systemPrompt?: string;
  temperature?: number;
  maxTokens?: number;
  responseFormat?: any;
  tools?: any[];
}

/**
 * Creates an agent function from an OpenAI client.
 * Auto-tracks token usage and cost for Bulwark budget enforcement.
 *
 * @param client - OpenAI client instance (from `new OpenAI()`)
 * @param opts - Model and generation options
 * @returns Agent function compatible with `Bulwark.wrap()`
 *
 * @example
 * ```typescript
 * import OpenAI from 'openai';
 * import { Bulwark } from 'bulwark';
 * import { openai } from 'bulwark/adapters';
 *
 * const client = new OpenAI();
 * const agent = openai(client, { model: 'gpt-4o', systemPrompt: 'You are helpful.' });
 * const safe = Bulwark.wrap(agent, contract);
 * const result = await safe.call('What is 2+2?');
 * // result.output = "2+2 = 4"
 * // Budget automatically tracks tokens and cost
 * ```
 */
export function openai(client: any, opts: OpenAIAdapterOptions = {}): AgentFn {
  const model = opts.model ?? 'gpt-4o';

  return async (input: any): Promise<AgentResult> => {
    const messages: any[] = [];

    if (opts.systemPrompt) {
      messages.push({ role: 'system', content: opts.systemPrompt });
    }

    if (typeof input === 'string') {
      messages.push({ role: 'user', content: input });
    } else if (Array.isArray(input)) {
      messages.push(...input);
    } else if (input?.messages) {
      messages.push(...input.messages);
    } else {
      messages.push({ role: 'user', content: JSON.stringify(input) });
    }

    const createOpts: any = { model, messages };
    if (opts.temperature !== undefined) createOpts.temperature = opts.temperature;
    if (opts.maxTokens !== undefined) createOpts.max_tokens = opts.maxTokens;
    if (opts.responseFormat) createOpts.response_format = opts.responseFormat;
    if (opts.tools) createOpts.tools = opts.tools;

    const response = await client.chat.completions.create(createOpts);

    const text = response.choices?.[0]?.message?.content ?? '';
    const usage = response.usage;
    const cost = usage ? calculateCost(model, usage) : undefined;

    return {
      __bulwark: true,
      output: text,
      tokensUsed: usage?.total_tokens,
      costIncurred: cost,
    };
  };
}

function calculateCost(model: string, usage: any): number {
  const pricing = PRICING[model];
  if (!pricing) return 0;
  const inputTokens = usage.prompt_tokens ?? 0;
  const outputTokens = usage.completion_tokens ?? 0;
  return (inputTokens * pricing.input + outputTokens * pricing.output) / 1_000_000;
}
