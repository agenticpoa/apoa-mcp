/**
 * @apoa/mcp -- APOA authorization for MCP servers.
 *
 * Two modes:
 * - Middleware: withAPOA(server, config) wraps your MCP server
 * - Proxy: createProxy(config) wraps a third-party MCP server
 */

// Middleware mode
export { withAPOA, type WithAPOAOptions, type SimpleMappings } from './guard.js';

// Proxy mode
export { createGateway as createProxy, type GatewayOptions } from './gateway.js';

// Configuration
export { GatewayConfigSchema, type GatewayConfig, type ToolMapping } from './config/schema.js';

// Authorization internals (for advanced use)
export { authorizeToolCall, extractToken, resolveMapping, type AuthorizationContext, type AuthorizationDecision } from './middleware/authorize.js';

// Key loading
export { loadPublicKey, loadIssuerKeys, type KeyResolver, type IssuerKeyResolver } from './keys.js';

// Persistent stores
export { SqliteRevocationStore } from './stores/sqlite-revocation.js';
export { SqliteAuditStore } from './stores/sqlite-audit.js';
export { SqliteReplayStore } from './stores/sqlite-replay.js';
export type { RevocationStore, AuditStore, AuditEntry, RevocationRecord, ReplayStore } from './stores/types.js';
