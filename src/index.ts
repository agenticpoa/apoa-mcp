#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from 'node:http';
import { GatewayConfigSchema } from './config/schema.js';
import { SqliteRevocationStore } from './stores/sqlite-revocation.js';
import { SqliteAuditStore } from './stores/sqlite-audit.js';
import { SqliteReplayStore } from './stores/sqlite-replay.js';
import { loadPublicKey, loadIssuerKeys } from './keys.js';
import { createGateway } from './gateway.js';

type TransportMode = 'stdio' | 'sse' | 'streamable-http';

function parseArgs(argv: string[]): { config: string; transport: TransportMode; port?: number } {
  const args = argv.slice(2);
  let config = './gateway.config.json';
  let transport: TransportMode | undefined;
  let port: number | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      console.error(`Usage: apoa-mcp [options]

Options:
  -c, --config <path>      Path to gateway config file (default: ./gateway.config.json)
  -t, --transport <mode>   Transport mode: stdio, sse, streamable-http (default: stdio)
  -p, --port <number>      Port for HTTP transports (overrides config)
  -h, --help               Show this help message
  -v, --version            Show version

Environment variables:
  GATEWAY_TRANSPORT        Transport mode (overridden by --transport flag)
`);
      process.exit(0);
    }

    if (arg === '--version' || arg === '-v') {
      console.error('apoa-mcp v0.1.0');
      process.exit(0);
    }

    if ((arg === '--config' || arg === '-c') && args[i + 1]) {
      config = args[++i];
      continue;
    }

    if ((arg === '--transport' || arg === '-t') && args[i + 1]) {
      const val = args[++i];
      if (!['stdio', 'sse', 'streamable-http'].includes(val)) {
        console.error(`Invalid transport mode: ${val}. Must be stdio, sse, or streamable-http.`);
        process.exit(1);
      }
      transport = val as TransportMode;
      continue;
    }

    if ((arg === '--port' || arg === '-p') && args[i + 1]) {
      port = parseInt(args[++i], 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        console.error(`Invalid port: ${args[i]}. Must be 1-65535.`);
        process.exit(1);
      }
      continue;
    }

    // Positional arg: treat first positional as config path for backwards compat
    if (!arg.startsWith('-')) {
      config = arg;
      continue;
    }

    console.error(`Unknown option: ${arg}. Use --help for usage.`);
    process.exit(1);
  }

  // CLI flag > env var > default
  const resolvedTransport = transport ?? (process.env.GATEWAY_TRANSPORT as TransportMode | undefined) ?? 'stdio';

  return { config, transport: resolvedTransport, port };
}

async function main() {
  const opts = parseArgs(process.argv);

  let rawConfig: unknown;
  try {
    rawConfig = JSON.parse(readFileSync(opts.config, 'utf-8'));
  } catch (err) {
    console.error(`Failed to read config from ${opts.config}: ${err}`);
    process.exit(1);
  }

  const config = GatewayConfigSchema.parse(rawConfig);

  // CLI port override
  if (opts.port) {
    (config as Record<string, unknown>).port = opts.port;
  }

  // Initialize persistent stores
  const revocationStore = new SqliteRevocationStore(config.dbPath);
  const auditStore = new SqliteAuditStore(config.dbPath);
  const replayStore = config.replayProtection?.enabled
    ? new SqliteReplayStore(config.dbPath)
    : undefined;

  // Load public key(s) for token verification
  const publicKey = await loadPublicKey(config);
  const issuerKeys = await loadIssuerKeys(config);
  if (publicKey || issuerKeys) {
    console.error('[gateway] Public key(s) loaded');
  } else {
    console.error('[gateway] WARNING: No public key configured. Token verification disabled.');
  }

  console.error('[gateway] APOA MCP Authorization Gateway v0.1.0');
  console.error(`[gateway] Database: ${config.dbPath}`);
  console.error(`[gateway] Tool mappings: ${config.toolMappings.length}`);
  console.error(`[gateway] Deny unmapped: ${config.denyUnmapped}`);

  const { server } = await createGateway({
    config,
    revocationStore,
    auditStore,
    publicKey,
    issuerKeys,
    replayStore,
  });

  const transportMode = opts.transport;

  if (transportMode === 'stdio') {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('[gateway] Gateway running on stdio');
  } else if (transportMode === 'sse') {
    await startHttpServer(config.port, 'sse', server);
  } else if (transportMode === 'streamable-http') {
    await startHttpServer(config.port, 'streamable-http', server);
  } else {
    console.error(`Unknown transport mode: ${transportMode}`);
    process.exit(1);
  }

  // Graceful shutdown
  const shutdown = () => {
    console.error('[gateway] Shutting down...');
    revocationStore.close();
    auditStore.close();
    replayStore?.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function startHttpServer(
  port: number,
  mode: 'sse' | 'streamable-http',
  mcpServer: import('@modelcontextprotocol/sdk/server/index.js').Server
): Promise<void> {
  // Track active SSE transports by session
  const sseTransports = new Map<string, SSEServerTransport>();

  const httpServer = createServer(async (req, res) => {
    // CORS headers for browser clients
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (mode === 'sse') {
      const url = new URL(req.url ?? '/', `http://localhost:${port}`);

      if (req.method === 'GET' && url.pathname === '/sse') {
        const transport = new SSEServerTransport('/messages', res);
        sseTransports.set(transport.sessionId, transport);
        transport.onclose = () => sseTransports.delete(transport.sessionId);
        await mcpServer.connect(transport);
        return;
      }

      if (req.method === 'POST' && url.pathname === '/messages') {
        const sessionId = url.searchParams.get('sessionId');
        if (!sessionId || !sseTransports.has(sessionId)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid or missing sessionId' }));
          return;
        }
        const transport = sseTransports.get(sessionId)!;
        await transport.handlePostMessage(req, res);
        return;
      }
    }

    if (mode === 'streamable-http') {
      if (req.url === '/mcp' && (req.method === 'POST' || req.method === 'GET')) {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => crypto.randomUUID() });
        await mcpServer.connect(transport);
        await transport.handleRequest(req, res);
        return;
      }
    }

    // Health check
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', version: '0.1.0', transport: mode }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  httpServer.listen(port, () => {
    console.error(`[gateway] Gateway running on http://localhost:${port} (${mode})`);
    if (mode === 'sse') {
      console.error(`[gateway] SSE endpoint: GET /sse`);
      console.error(`[gateway] Message endpoint: POST /messages?sessionId=<id>`);
    } else {
      console.error(`[gateway] Streamable HTTP endpoint: POST /mcp`);
    }
  });
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
