import { Bulwark } from './index';
import {
  Contract, HarnessedAgent, SequenceConfig, RuleContext,
} from './types';
import * as http from 'http';

// ── MCP Tool Definitions ────────────────────────────────────────────────────

const TOOLS = [
  {
    name: 'bulwark_create_contract',
    description: 'Create a behavioral contract for an AI agent with preconditions, postconditions, invariants, and budget limits',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Contract name' },
        description: { type: 'string', description: 'Contract description' },
        maxTokens: { type: 'number', description: 'Maximum token budget' },
        maxCost: { type: 'number', description: 'Maximum cost in dollars' },
        maxActions: { type: 'number', description: 'Maximum number of actions' },
        maxSteps: { type: 'number', description: 'Maximum sequence length' },
        rules: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              phase: { type: 'string', enum: ['pre', 'post', 'invariant'] },
              description: { type: 'string' },
            },
            required: ['name', 'phase'],
          },
          description: 'Contract rules (checks are added programmatically)',
        },
      },
      required: ['name'],
    },
  },
  {
    name: 'bulwark_validate_input',
    description: 'Check if an input would pass a contract\'s preconditions',
    inputSchema: {
      type: 'object',
      properties: {
        contractName: { type: 'string', description: 'Name of the contract to check against' },
        input: { description: 'The input to validate' },
      },
      required: ['contractName', 'input'],
    },
  },
  {
    name: 'bulwark_get_metrics',
    description: 'Get session metrics for a harnessed agent (calls, violations, drift score, budget usage)',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: 'Session ID of the harnessed agent' },
      },
      required: ['sessionId'],
    },
  },
  {
    name: 'bulwark_get_drift',
    description: 'Get behavioral drift analysis using EWMA and CUSUM statistical process control',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: 'Session ID' },
      },
      required: ['sessionId'],
    },
  },
  {
    name: 'bulwark_get_audit',
    description: 'Generate a compliance audit report for a session',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: 'Session ID' },
      },
      required: ['sessionId'],
    },
  },
  {
    name: 'bulwark_get_budget',
    description: 'Get current budget snapshot (tokens, cost, actions used vs limits)',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: 'Session ID' },
      },
      required: ['sessionId'],
    },
  },
  {
    name: 'bulwark_list_contracts',
    description: 'List all registered contracts',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'bulwark_list_sessions',
    description: 'List all active harnessed agent sessions',
    inputSchema: { type: 'object', properties: {} },
  },
];

// ── MCP Server State ────────────────────────────────────────────────────────

const contracts = new Map<string, Contract & { sequenceConfig?: SequenceConfig }>();
const sessions = new Map<string, HarnessedAgent>();

// ── Tool Handlers ───────────────────────────────────────────────────────────

function handleTool(name: string, args: any): any {
  switch (name) {
    case 'bulwark_create_contract': {
      const builder = Bulwark.contract(args.name);
      if (args.description) builder.description(args.description);
      if (args.maxSteps) builder.maxSteps(args.maxSteps);

      const budgetConfig: any = {};
      if (args.maxTokens) budgetConfig.maxTokens = args.maxTokens;
      if (args.maxCost) budgetConfig.maxCost = args.maxCost;
      if (args.maxActions) budgetConfig.maxActions = args.maxActions;
      if (Object.keys(budgetConfig).length > 0) builder.budget(budgetConfig);

      const contract = builder.build();
      contracts.set(args.name, contract);

      return {
        success: true,
        contract: {
          name: contract.name,
          description: contract.description,
          preconditions: contract.preconditions.length,
          postconditions: contract.postconditions.length,
          invariants: contract.invariants.length,
          budget: contract.budget,
        },
      };
    }

    case 'bulwark_validate_input': {
      const contract = contracts.get(args.contractName);
      if (!contract) return { error: `Contract '${args.contractName}' not found` };

      // Run preconditions synchronously where possible
      const violations: any[] = [];
      const ctx: RuleContext = {
        input: args.input,
        state: {},
        history: [],
        metrics: {
          totalCalls: 0, totalViolations: 0, totalBlocked: 0, totalRecovered: 0,
          violationRate: 0, blockRate: 0, avgLatencyMs: 0,
          totalTokens: 0, totalCost: 0, startTime: Date.now(),
          lastCallTime: Date.now(), driftScore: 0,
        },
      };

      for (const rule of contract.preconditions) {
        try {
          const result = rule.check(ctx);
          if (result === false) {
            violations.push({ rule: rule.name, severity: rule.severity });
          }
        } catch (err) {
          violations.push({ rule: rule.name, severity: rule.severity, error: String(err) });
        }
      }

      return {
        valid: violations.length === 0,
        violations,
      };
    }

    case 'bulwark_get_metrics': {
      const agent = sessions.get(args.sessionId);
      if (!agent) return { error: `Session '${args.sessionId}' not found` };
      return agent.getMetrics();
    }

    case 'bulwark_get_drift': {
      const agent = sessions.get(args.sessionId);
      if (!agent) return { error: `Session '${args.sessionId}' not found` };
      return agent.getDrift();
    }

    case 'bulwark_get_audit': {
      const agent = sessions.get(args.sessionId);
      if (!agent) return { error: `Session '${args.sessionId}' not found` };
      const report = agent.getAudit();
      return { summary: report.summary, complianceRate: report.complianceRate, totalActions: report.totalActions };
    }

    case 'bulwark_get_budget': {
      const agent = sessions.get(args.sessionId);
      if (!agent) return { error: `Session '${args.sessionId}' not found` };
      return agent.getBudget();
    }

    case 'bulwark_list_contracts': {
      return [...contracts.entries()].map(([name, c]) => ({
        name,
        description: c.description,
        rules: c.preconditions.length + c.postconditions.length + c.invariants.length,
      }));
    }

    case 'bulwark_list_sessions': {
      return [...sessions.entries()].map(([id, agent]) => ({
        sessionId: id,
        contract: agent.contract.name,
        metrics: agent.getMetrics(),
      }));
    }

    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ── MCP JSON-RPC Server ─────────────────────────────────────────────────────

function handleJsonRpc(request: any): any {
  const { method, params, id } = request;

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'bulwark', version: '1.0.0' },
          capabilities: { tools: {} },
        },
      };

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id,
        result: { tools: TOOLS },
      };

    case 'tools/call': {
      const { name, arguments: args } = params;
      const result = handleTool(name, args ?? {});
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2),
          }],
        },
      };
    }

    default:
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

// ── stdio transport ─────────────────────────────────────────────────────────

export function startMCPServer() {
  let buffer = '';

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk: string) => {
    buffer += chunk;

    // Process complete JSON-RPC messages (newline-delimited)
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const request = JSON.parse(trimmed);
        const response = handleJsonRpc(request);
        if (response) {
          process.stdout.write(JSON.stringify(response) + '\n');
        }
      } catch {
        // Invalid JSON, skip
      }
    }
  });

  process.stderr.write('Bulwark MCP server started (stdio)\n');
}

// ── Programmatic access ─────────────────────────────────────────────────────

export function registerContract(contract: Contract & { sequenceConfig?: SequenceConfig }) {
  contracts.set(contract.name, contract);
}

export function registerSession(agent: HarnessedAgent) {
  sessions.set(agent.sessionId, agent);
}

export { contracts, sessions, handleTool, TOOLS };

// Auto-start if run directly
if (require.main === module) {
  startMCPServer();
}
