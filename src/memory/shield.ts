/**
 * Memory Shield — Drop-in protection for any memory system.
 *
 * Wraps any object with add/get/search methods and intercepts all
 * operations through the memory firewall. Zero dependencies beyond
 * the firewall itself.
 *
 * Supports:
 *   - LangChain BaseMemory (saveContext / loadMemoryVariables)
 *   - Mem0 Memory (add / search / get / getAll)
 *   - Any custom memory with a similar interface
 *
 * @example
 * ```typescript
 * import { shield } from 'bulwark-ai/memory';
 * import { Memory } from 'mem0ai/oss';
 *
 * const mem = new Memory({ ... });
 * const safe = shield(mem, { agentId: 'my-agent' });
 *
 * // All operations now go through the firewall
 * await safe.add('User prefers dark mode', { userId: 'u1' });
 * const results = await safe.search('preferences', { userId: 'u1' });
 * ```
 */

import { MemoryFirewall } from './firewall';
import type { MemorySource, FirewallConfig, WriteResult } from './types';

export interface ShieldOptions {
  /** Agent ID for provenance tracking. */
  agentId?: string;
  /** Session ID for provenance tracking. */
  sessionId?: string;
  /** Firewall configuration overrides. */
  config?: Partial<FirewallConfig>;
  /** Called when a write is blocked. */
  onBlocked?: (content: any, result: WriteResult) => void;
  /** Called when an attack pattern is detected. */
  onAttack?: (content: any, patterns: string[]) => void;
}

/**
 * Shield a Mem0 Memory instance.
 * Wraps add/search/get/getAll/update with firewall protection.
 */
export function shieldMem0(mem0: any, opts: ShieldOptions = {}): any {
  if (!mem0 || typeof mem0.add !== 'function') {
    throw new Error('Expected a Mem0 Memory instance with .add() method');
  }

  const fw = new MemoryFirewall(opts.config);
  const agentId = opts.agentId ?? 'mem0-agent';
  const sessionId = opts.sessionId ?? `session-${Date.now()}`;

  function makeSource(protocol: MemorySource['protocol'] = 'direct'): MemorySource {
    return { agentId, protocol, sessionId };
  }

  return {
    /** Protected add — scans content through firewall before storing. */
    async add(messages: any, config?: any): Promise<any> {
      const content = typeof messages === 'string' ? messages : messages;
      const source = makeSource(config?.agentId ? 'tool-call' : 'direct');
      if (config?.agentId) source.agentId = config.agentId;

      const result = fw.write(content, source);

      if (!result.allowed) {
        opts.onBlocked?.(content, result);
        if (result.detectedPatterns.length > 0) {
          opts.onAttack?.(content, result.detectedPatterns);
        }
        return { results: [], blocked: true, reason: result.reason };
      }

      return mem0.add(messages, config);
    },

    /** Protected search — filters results by trust score. */
    async search(query: string, config?: any): Promise<any> {
      const results = await mem0.search(query, config);

      if (results?.results) {
        const filtered = [];
        for (const item of results.results) {
          // Check each result through the firewall's read path
          const writeResult = fw.write(item.memory ?? item, makeSource('import'));
          if (writeResult.allowed) {
            filtered.push(item);
          }
        }
        return { ...results, results: filtered };
      }

      return results;
    },

    /** Pass-through get (single item, already stored). */
    async get(memoryId: string): Promise<any> {
      return mem0.get(memoryId);
    },

    /** Pass-through getAll (already stored). */
    async getAll(config?: any): Promise<any> {
      return mem0.getAll(config);
    },

    /** Protected update — scans new content before allowing update. */
    async update(memoryId: string, data: string): Promise<any> {
      const result = fw.write(data, makeSource('tool-call'));

      if (!result.allowed) {
        opts.onBlocked?.(data, result);
        return { message: `Update blocked: ${result.reason}` };
      }

      return mem0.update(memoryId, data);
    },

    /** Pass-through delete. */
    async delete(memoryId: string): Promise<any> {
      return mem0.delete(memoryId);
    },

    /** Pass-through deleteAll. */
    async deleteAll(config?: any): Promise<any> {
      return mem0.deleteAll(config);
    },

    /** Pass-through history. */
    async history(memoryId: string): Promise<any> {
      return mem0.history(memoryId);
    },

    /** Pass-through reset. */
    async reset(): Promise<void> {
      fw.reset();
      return mem0.reset();
    },

    /** Get the underlying firewall for status/audit. */
    getFirewall(): MemoryFirewall {
      return fw;
    },
  };
}

/**
 * Shield a LangChain BaseMemory instance.
 * Wraps saveContext / loadMemoryVariables with firewall protection.
 *
 * Compatible with BufferMemory, VectorStoreRetrieverMemory,
 * ConversationSummaryMemory, and any BaseMemory subclass.
 */
export function shieldLangChain(memory: any, opts: ShieldOptions = {}): any {
  if (!memory || typeof memory.loadMemoryVariables !== 'function') {
    throw new Error('Expected a LangChain BaseMemory with .loadMemoryVariables() method');
  }

  const fw = new MemoryFirewall(opts.config);
  const agentId = opts.agentId ?? 'langchain-agent';
  const sessionId = opts.sessionId ?? `session-${Date.now()}`;

  function makeSource(): MemorySource {
    return { agentId, protocol: 'tool-call', sessionId };
  }

  // Wrap the memory object, preserving its prototype chain
  const original = {
    saveContext: memory.saveContext.bind(memory),
    loadMemoryVariables: memory.loadMemoryVariables.bind(memory),
  };

  // Override saveContext — intercept writes
  memory.saveContext = async function(
    inputValues: Record<string, any>,
    outputValues: Record<string, any>,
  ): Promise<void> {
    // Scan both input and output for poisoning
    const inputResult = fw.write(inputValues, makeSource());
    if (!inputResult.allowed) {
      opts.onBlocked?.(inputValues, inputResult);
      if (inputResult.detectedPatterns.length > 0) {
        opts.onAttack?.(inputValues, inputResult.detectedPatterns);
      }
      return; // Block the save
    }

    const outputResult = fw.write(outputValues, makeSource());
    if (!outputResult.allowed) {
      opts.onBlocked?.(outputValues, outputResult);
      if (outputResult.detectedPatterns.length > 0) {
        opts.onAttack?.(outputValues, outputResult.detectedPatterns);
      }
      return; // Block the save
    }

    return original.saveContext(inputValues, outputValues);
  };

  // Override loadMemoryVariables — audit reads
  memory.loadMemoryVariables = async function(
    values: Record<string, any>,
  ): Promise<Record<string, any>> {
    const result = await original.loadMemoryVariables(values);

    // Scan retrieved memories for poisoning (defense at retrieval time)
    for (const [key, value] of Object.entries(result)) {
      if (typeof value === 'string') {
        const scanResult = fw.write(value, { agentId, protocol: 'import', sessionId });
        if (!scanResult.allowed) {
          // Filter out poisoned memories
          result[key] = typeof value === 'string' ? '' : [];
          opts.onBlocked?.(value, scanResult);
        }
      }
    }

    return result;
  };

  // Attach firewall access
  memory.getFirewall = () => fw;

  return memory;
}

/**
 * Generic shield — auto-detects the memory system type and wraps it.
 *
 * @example
 * ```typescript
 * import { shield } from 'bulwark-ai/memory';
 *
 * // Works with Mem0
 * const safeMem0 = shield(mem0Instance, { agentId: 'my-agent' });
 *
 * // Works with LangChain
 * const safeLangChain = shield(bufferMemory, { agentId: 'my-agent' });
 * ```
 */
export function shield(memorySystem: any, opts: ShieldOptions = {}): any {
  if (!memorySystem) {
    throw new Error('Expected a memory system instance');
  }

  // Detect Mem0
  if (typeof memorySystem.add === 'function' && typeof memorySystem.search === 'function') {
    return shieldMem0(memorySystem, opts);
  }

  // Detect LangChain BaseMemory
  if (typeof memorySystem.loadMemoryVariables === 'function' && typeof memorySystem.saveContext === 'function') {
    return shieldLangChain(memorySystem, opts);
  }

  throw new Error('Unrecognized memory system. Use shieldMem0() or shieldLangChain() directly.');
}
