import { AgentFn, AgentResult } from '../types';

const PRICING: Record<string, { input: number; output: number }> = {
  'claude-opus-4-6': { input: 15.00, output: 75.00 },
  'claude-sonnet-4-6': { input: 3.00, output: 15.00 },
  'claude-haiku-4-5': { input: 0.80, output: 4.00 },
};

export interface AnthropicAdapterOptions {
  model?: string;
  systemPrompt?: string;
  maxTokens?: number;
  temperature?: number;
  tools?: any[];
}

/**
 * Creates an agent function from an Anthropic client.
 * Auto-tracks token usage and cost for Bulwark budget enforcement.
 *
 * @example
 * ```typescript
 * import Anthropic from '@anthropic-ai/sdk';
 * import { Bulwark } from 'bulwark';
 * import { anthropic } from 'bulwark/adapters';
 *
 * const client = new Anthropic();
 * const agent = anthropic(client, { model: 'claude-sonnet-4-6' });
 * const safe = Bulwark.wrap(agent, contract);
 * ```
 */
export function anthropic(client: any, opts: AnthropicAdapterOptions = {}): AgentFn {
  const model = opts.model ?? 'claude-sonnet-4-6';

  return async (input: any): Promise<AgentResult> => {
    const messages: any[] = [];

    if (typeof input === 'string') {
      messages.push({ role: 'user', content: input });
    } else if (Array.isArray(input)) {
      messages.push(...input);
    } else if (input?.messages) {
      messages.push(...input.messages);
    } else {
      messages.push({ role: 'user', content: JSON.stringify(input) });
    }

    const createOpts: any = {
      model,
      messages,
      max_tokens: opts.maxTokens ?? 4096,
    };
    if (opts.systemPrompt) createOpts.system = opts.systemPrompt;
    if (opts.temperature !== undefined) createOpts.temperature = opts.temperature;
    if (opts.tools) createOpts.tools = opts.tools;

    const response = await client.messages.create(createOpts);

    const text = response.content
      ?.filter((b: any) => b.type === 'text')
      .map((b: any) => b.text)
      .join('') ?? '';

    const usage = response.usage;
    const inputTokens = usage?.input_tokens ?? 0;
    const outputTokens = usage?.output_tokens ?? 0;
    const totalTokens = inputTokens + outputTokens;
    const cost = calculateCost(model, inputTokens, outputTokens);

    return {
      __bulwark: true,
      output: text,
      tokensUsed: totalTokens,
      costIncurred: cost,
    };
  };
}

function calculateCost(model: string, inputTokens: number, outputTokens: number): number {
  const pricing = PRICING[model];
  if (!pricing) return 0;
  return (inputTokens * pricing.input + outputTokens * pricing.output) / 1_000_000;
}
