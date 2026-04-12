import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { GatewayConfig } from './config/schema.js';
import type { RevocationStore, AuditStore, ReplayStore } from './stores/types.js';
import type { IssuerKeyResolver } from './keys.js';
import { authorizeToolCall, type AuthorizationContext } from './middleware/authorize.js';
import type { KeyResolver } from './keys.js';

export interface GatewayOptions {
  config: GatewayConfig;
  revocationStore: RevocationStore;
  auditStore: AuditStore;
  publicKey?: KeyResolver;
  issuerKeys?: IssuerKeyResolver;
  replayStore?: ReplayStore;
}

/**
 * Create and start the APOA MCP Authorization Gateway.
 *
 * The gateway acts as a transparent MCP proxy:
 * - Downstream clients connect to the gateway as if it were the MCP server
 * - The gateway connects upstream to the real MCP server
 * - Tool calls are intercepted and authorized against APOA tokens
 * - Authorized calls are forwarded; unauthorized calls are denied
 * - All decisions are logged to the persistent audit store
 */
export async function createGateway(options: GatewayOptions) {
  const { config, revocationStore, auditStore, publicKey, issuerKeys, replayStore } = options;

  const authCtx: AuthorizationContext = {
    config,
    revocationStore,
    auditStore,
    publicKey,
    issuerKeys,
    replayStore,
  };

  // --- Upstream MCP client (connects to the real server) ---
  let upstreamClient: Client | null = null;

  if (config.upstream.transport === 'stdio' && config.upstream.command) {
    const transport = new StdioClientTransport({
      command: config.upstream.command,
      args: config.upstream.args,
    });

    upstreamClient = new Client(
      { name: 'apoa-gateway', version: '0.1.0' },
      { capabilities: {} }
    );

    await upstreamClient.connect(transport);
    console.error('[gateway] Connected to upstream MCP server via stdio');
  }

  // --- Downstream MCP server (clients connect to this) ---
  const server = new Server(
    {
      name: 'apoa-mcp-gateway',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Proxy tool listing from upstream
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    if (!upstreamClient) {
      return { tools: [] };
    }
    const result = await upstreamClient.listTools();
    return { tools: result.tools };
  });

  // Intercept tool calls with APOA authorization
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name: toolName, arguments: toolArgs } = request.params;
    const params = (toolArgs ?? {}) as Record<string, unknown>;

    // Authorize the tool call
    const decision = await authorizeToolCall(toolName, params, authCtx);

    if (!decision.authorized) {
      console.error(`[gateway] DENIED: ${toolName} - ${decision.reason}`);
      return {
        content: [
          {
            type: 'text' as const,
            text: `Authorization denied: ${decision.reason}`,
          },
        ],
        isError: true,
      };
    }

    console.error(`[gateway] ALLOWED: ${toolName} -> ${decision.service}:${decision.scope}`);

    // Forward to upstream
    if (!upstreamClient) {
      return {
        content: [
          {
            type: 'text' as const,
            text: 'No upstream MCP server connected',
          },
        ],
        isError: true,
      };
    }

    // Strip the _meta.apoa_token before forwarding (don't leak tokens upstream)
    const forwardParams = { ...params };
    if (forwardParams._meta) {
      const meta = { ...(forwardParams._meta as Record<string, unknown>) };
      delete meta.apoa_token;
      forwardParams._meta = Object.keys(meta).length > 0 ? meta : undefined;
    }

    const result = await upstreamClient.callTool({
      name: toolName,
      arguments: forwardParams,
    });

    return result;
  });

  return { server, upstreamClient };
}
