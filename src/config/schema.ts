import { z } from 'zod';

const ArgumentMatcherSchema = z.object({
  equals: z.unknown().optional(),
  startsWith: z.string().optional(),
  endsWith: z.string().optional(),
  contains: z.string().optional(),
  matches: z.string().optional(),
  oneOf: z.array(z.unknown()).optional(),
});

/**
 * Maps MCP tool names to APOA service + scope pairs.
 * This is the core configuration that tells the gateway
 * how to translate MCP tool calls into APOA authorization checks.
 *
 * Optional `when` field enables argument-aware scoping:
 * mappings with `when` are evaluated first (by priority),
 * then unconditional mappings serve as fallback.
 */
export const ToolMappingSchema = z.object({
  /** MCP tool name (e.g., "read_file", "search_web") */
  tool: z.string().min(1),
  /** APOA service identifier (e.g., "filesystem", "web-search.example.com") */
  service: z.string().min(1),
  /** APOA scope/action (e.g., "files:read", "search:execute") */
  scope: z.string().min(1),
  /** Optional argument conditions for this mapping */
  when: z.record(z.string(), ArgumentMatcherSchema).optional(),
  /** Priority for ordering (higher = checked first). Default 0. */
  priority: z.number().int().default(0),
});

export const GatewayConfigSchema = z.object({
  /** Gateway server port */
  port: z.number().int().positive().default(3100),

  /** Upstream MCP server transport config */
  upstream: z.object({
    /** Transport type */
    transport: z.enum(['stdio', 'sse', 'streamable-http']),
    /** Command to spawn (stdio transport) */
    command: z.string().optional(),
    /** Args for the command (stdio transport) */
    args: z.array(z.string()).optional(),
    /** URL for HTTP-based transports */
    url: z.string().url().optional(),
  }),

  /** Tool name -> APOA service+scope mappings */
  toolMappings: z.array(ToolMappingSchema),

  /** Default APOA service for unmapped tools (deny if not set) */
  defaultService: z.string().optional(),

  /** Default scope pattern for unmapped tools */
  defaultScope: z.string().optional(),

  /** Path to SQLite database for revocation + audit persistence */
  dbPath: z.string().default('./gateway.db'),

  /** JWKS URL or local public key path for token verification */
  publicKeySource: z.union([
    z.object({ type: z.literal('jwks'), url: z.string().url() }),
    z.object({ type: z.literal('file'), path: z.string() }),
    z.object({
      type: z.literal('per-issuer'),
      issuers: z.record(z.string(), z.union([
        z.object({ type: z.literal('jwks'), url: z.string().url() }),
        z.object({ type: z.literal('file'), path: z.string() }),
      ])),
      default: z.union([
        z.object({ type: z.literal('jwks'), url: z.string().url() }),
        z.object({ type: z.literal('file'), path: z.string() }),
      ]).optional(),
    }),
  ]).optional(),

  /** Whether to deny unmapped tools (true) or allow with warning (false) */
  denyUnmapped: z.boolean().default(true),

  /** Auto-map unmapped tools to tool_name -> tool_name:call (default: true) */
  autoMapping: z.boolean().default(true),

  /** Clock skew tolerance in seconds for token validation */
  clockSkewSeconds: z.number().int().min(0).default(30),

  /** Maximum allowed delegation chain depth */
  maxDelegationDepth: z.number().int().min(0).default(5),

  /** JTI-based replay protection (opt-in) */
  replayProtection: z.object({
    enabled: z.boolean().default(false),
    /** How long to remember seen JTIs, in seconds */
    windowSeconds: z.number().int().positive().default(3600),
  }).optional(),
});

export type ToolMapping = z.infer<typeof ToolMappingSchema>;
export type GatewayConfig = z.output<typeof GatewayConfigSchema>;
