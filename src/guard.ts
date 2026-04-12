/**
 * withAPOA() -- middleware that wraps an MCP Server with APOA authorization.
 *
 * Usage:
 *   import { Server } from '@modelcontextprotocol/sdk/server/index.js';
 *   import { withAPOA } from '@apoa/mcp';
 *
 *   const server = new Server({ name: 'my-server', version: '1.0.0' }, { capabilities: { tools: {} } });
 *   withAPOA(server, { key: publicKey, mappings: { read_file: 'filesystem:files:read' } });
 */

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { KeyResolver } from './keys.js';
import { authorizeToolCall, type AuthorizationContext } from './middleware/authorize.js';
import { GatewayConfigSchema, type ToolMapping, type GatewayConfig } from './config/schema.js';
import type { RevocationStore, AuditStore, ReplayStore } from './stores/types.js';

export interface SimpleMappings {
  [toolName: string]: string; // "service:scope" or "service:scope:detail"
}

export interface WithAPOAOptions {
  /** Public key for token verification */
  key: KeyResolver;

  /** Tool-to-scope mappings. Simple format: { read_file: 'filesystem:files:read' }
   *  Or full format: [{ tool: 'read_file', service: 'filesystem', scope: 'files:read' }] */
  mappings?: SimpleMappings | ToolMapping[];

  /** Revocation store (defaults to in-memory) */
  revocationStore?: RevocationStore;

  /** Audit store (defaults to in-memory) */
  auditStore?: AuditStore;

  /** Replay protection store */
  replayStore?: ReplayStore;

  /** Deny tools with no mapping (default: false for middleware, true for proxy) */
  denyUnmapped?: boolean;

  /** Enable auto-mapping: unmapped tools get tool_name -> tool_name:call (default: true) */
  autoMapping?: boolean;

  /** Clock skew tolerance in seconds (default: 30) */
  clockSkewSeconds?: number;

  /** Enable apoa.check dry-run tool (default: false) */
  enableCheckTool?: boolean;
}

/**
 * Parse simple mapping format: "filesystem:files:read" -> { service: "filesystem", scope: "files:read" }
 * The first colon-separated segment is the service, the rest is the scope.
 */
function parseSimpleMapping(toolName: string, mapping: string): ToolMapping {
  const firstColon = mapping.indexOf(':');
  if (firstColon === -1) {
    return { tool: toolName, service: mapping, scope: 'call', priority: 0 };
  }
  return {
    tool: toolName,
    service: mapping.slice(0, firstColon),
    scope: mapping.slice(firstColon + 1),
    priority: 0,
  };
}

function normalizeToolMappings(mappings?: SimpleMappings | ToolMapping[]): ToolMapping[] {
  if (!mappings) return [];
  if (Array.isArray(mappings)) return mappings;

  return Object.entries(mappings).map(([tool, mapping]) => parseSimpleMapping(tool, mapping));
}

/**
 * Wrap an MCP Server with APOA authorization.
 * Intercepts CallToolRequest, authorizes via APOA token, then runs the original handler.
 */
export function withAPOA(server: Server, options: WithAPOAOptions): void {
  const toolMappings = normalizeToolMappings(options.mappings);

  // Build a minimal GatewayConfig for the authorization context
  const config: GatewayConfig = {
    port: 0,
    upstream: { transport: 'stdio' },
    toolMappings,
    denyUnmapped: options.denyUnmapped ?? false,
    autoMapping: options.autoMapping ?? true,
    dbPath: ':memory:',
    clockSkewSeconds: options.clockSkewSeconds ?? 30,
    maxDelegationDepth: 5,
  };

  // In-memory stores as defaults for middleware mode
  const revocationStore = options.revocationStore ?? createMemoryRevocationStore();
  const auditStore = options.auditStore ?? createMemoryAuditStore();

  const authCtx: AuthorizationContext = {
    config,
    revocationStore,
    auditStore,
    publicKey: options.key,
    replayStore: options.replayStore,
  };

  // Store reference to original handler so we can wrap it
  const originalHandlers = new Map<string, Function>();

  // Intercept CallToolRequest
  const originalSetRequestHandler = server.setRequestHandler.bind(server);

  // Override setRequestHandler to capture tool handlers
  server.setRequestHandler = ((schema: any, handler: any) => {
    if (schema === CallToolRequestSchema) {
      // Wrap the tool handler with authorization
      const wrappedHandler = async (request: any) => {
        const { name: toolName, arguments: toolArgs } = request.params;
        const params = (toolArgs ?? {}) as Record<string, unknown>;

        // Handle apoa.check dry-run tool
        if (options.enableCheckTool && toolName === 'apoa.check') {
          return handleCheckTool(params, authCtx);
        }

        const decision = await authorizeToolCall(toolName, params, authCtx);

        if (!decision.authorized) {
          return {
            content: [{ type: 'text' as const, text: `Authorization denied: ${decision.reason}` }],
            isError: true,
          };
        }

        // Strip _meta.apoa_token before passing to the actual handler
        const cleanParams = { ...params };
        if (cleanParams._meta) {
          const meta = { ...(cleanParams._meta as Record<string, unknown>) };
          delete meta.apoa_token;
          cleanParams._meta = Object.keys(meta).length > 0 ? meta : undefined;
        }

        return handler({ ...request, params: { ...request.params, arguments: cleanParams } });
      };

      originalSetRequestHandler(schema, wrappedHandler);
    } else if (schema === ListToolsRequestSchema && options.enableCheckTool) {
      // Inject apoa.check tool into the tool list
      const wrappedHandler = async (request: any) => {
        const result = await handler(request);
        result.tools = result.tools ?? [];
        result.tools.push({
          name: 'apoa.check',
          description: 'Dry-run authorization check. Returns whether a tool call would be authorized without executing it.',
          inputSchema: {
            type: 'object',
            properties: {
              tool: { type: 'string', description: 'Tool name to check' },
              arguments: { type: 'object', description: 'Tool arguments (for conditional mapping resolution)' },
            },
            required: ['tool'],
          },
        });
        return result;
      };
      originalSetRequestHandler(schema, wrappedHandler);
    } else {
      originalSetRequestHandler(schema, handler);
    }
  }) as typeof server.setRequestHandler;
}

async function handleCheckTool(
  params: Record<string, unknown>,
  ctx: AuthorizationContext
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const targetTool = params.tool as string;
  const targetArgs = (params.arguments as Record<string, unknown>) ?? {};

  // Merge _meta from the check call into the target args for token extraction
  const mergedArgs = { ...targetArgs, _meta: params._meta };

  const decision = await authorizeToolCall(targetTool, mergedArgs, ctx);

  const trace = {
    tool: targetTool,
    authorized: decision.authorized,
    reason: decision.reason,
    service: decision.service,
    scope: decision.scope,
    tokenId: decision.tokenId,
  };

  return {
    content: [{ type: 'text' as const, text: JSON.stringify(trace, null, 2) }],
  };
}

// Minimal in-memory stores for middleware mode (no SQLite dependency required)
function createMemoryRevocationStore(): RevocationStore {
  const records = new Map<string, any>();
  return {
    add: async (record: any) => { records.set(record.tokenId, record); },
    check: async (tokenId: string) => records.get(tokenId) ?? null,
    checkAny: async (tokenIds: string[]) => {
      for (const id of tokenIds) {
        const r = records.get(id);
        if (r) return r;
      }
      return null;
    },
    list: async (principalId: string) => [...records.values()].filter((r) => r.revokedBy === principalId),
  };
}

function createMemoryAuditStore(): AuditStore {
  const entries: any[] = [];
  return {
    append: async (entry: any) => { entries.push(entry); },
    query: async (tokenId: string) => entries.filter((e) => e.tokenId === tokenId),
    queryByService: async (service: string) => entries.filter((e) => e.service === service),
  };
}
