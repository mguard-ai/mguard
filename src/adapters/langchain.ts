import { AgentFn, AgentResult } from '../types';

export interface LangChainAdapterOptions {
  costPerInputToken?: number;
  costPerOutputToken?: number;
}

/**
 * Wraps a LangChain runnable (chain, agent, LLM) as a Bulwark agent function.
 * Works with any object that has `.invoke()` — ChatModels, chains, agents, tools.
 *
 * @param runnable - Any LangChain Runnable (ChatOpenAI, AgentExecutor, RunnableSequence, etc.)
 * @param opts - Cost tracking options
 * @returns Agent function compatible with `Bulwark.wrap()`
 *
 * @example
 * ```typescript
 * import { ChatOpenAI } from '@langchain/openai';
 * import { Bulwark } from 'bulwark';
 * import { langchain } from 'bulwark/adapters';
 *
 * const llm = new ChatOpenAI({ model: 'gpt-4o' });
 * const agent = langchain(llm);
 * const safe = Bulwark.wrap(agent, contract);
 * const result = await safe.call('Summarize this document...');
 * ```
 *
 * @example
 * ```typescript
 * // With an AgentExecutor
 * import { AgentExecutor } from 'langchain/agents';
 * const executor = AgentExecutor.fromAgentAndTools({ agent, tools });
 * const safe = Bulwark.wrap(langchain(executor), contract);
 * const result = await safe.call({ input: 'Find flights to Paris' });
 * ```
 */
export function langchain(runnable: any, opts: LangChainAdapterOptions = {}): AgentFn {
  if (!runnable || typeof runnable.invoke !== 'function') {
    throw new Error('Expected a LangChain Runnable with an .invoke() method');
  }

  return async (input: any): Promise<AgentResult> => {
    const result = await runnable.invoke(input);

    // Extract text from various LangChain output types
    let output: any;
    let tokensUsed: number | undefined;
    let costIncurred: number | undefined;

    if (typeof result === 'string') {
      // Plain string (from StringOutputParser or simple chains)
      output = result;
    } else if (result?.content !== undefined) {
      // AIMessage from ChatModels
      output = typeof result.content === 'string'
        ? result.content
        : JSON.stringify(result.content);

      // Extract token usage from response metadata
      const usage = result.response_metadata?.usage
        ?? result.usage_metadata
        ?? result.response_metadata?.tokenUsage;
      if (usage) {
        const inputTokens = usage.prompt_tokens ?? usage.input_tokens ?? usage.promptTokens ?? 0;
        const outputTokens = usage.completion_tokens ?? usage.output_tokens ?? usage.completionTokens ?? 0;
        tokensUsed = inputTokens + outputTokens;

        if (opts.costPerInputToken && opts.costPerOutputToken) {
          costIncurred = inputTokens * opts.costPerInputToken + outputTokens * opts.costPerOutputToken;
        }
      }
    } else if (result?.output !== undefined) {
      // AgentExecutor output
      output = result.output;
    } else {
      output = typeof result === 'object' ? JSON.stringify(result) : String(result);
    }

    return {
      __bulwark: true,
      output,
      tokensUsed,
      costIncurred,
    };
  };
}
