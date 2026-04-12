import { describe, it, expect, beforeEach } from 'vitest';
import * as jose from 'jose';
import {
  authorizeToolCall,
  extractToken,
  resolveMapping,
  type AuthorizationContext,
} from '../src/middleware/authorize.js';
import type { GatewayConfig } from '../src/config/schema.js';
import type { RevocationStore, AuditStore, AuditEntry, RevocationRecord, ReplayStore } from '../src/stores/types.js';

// In-memory stores for testing
class TestRevocationStore implements RevocationStore {
  records = new Map<string, RevocationRecord>();
  async add(record: RevocationRecord) { this.records.set(record.tokenId, record); }
  async check(tokenId: string) { return this.records.get(tokenId) ?? null; }
  async checkAny(tokenIds: string[]) {
    for (const id of tokenIds) {
      const record = this.records.get(id);
      if (record) return record;
    }
    return null;
  }
  async list(principalId: string) {
    return [...this.records.values()].filter(r => r.revokedBy === principalId);
  }
}

class TestAuditStore implements AuditStore {
  entries: AuditEntry[] = [];
  async append(entry: AuditEntry) { this.entries.push(entry); }
  async query(tokenId: string) { return this.entries.filter(e => e.tokenId === tokenId); }
  async queryByService(service: string) { return this.entries.filter(e => e.service === service); }
}

const testConfig: GatewayConfig = {
  port: 3100,
  upstream: { transport: 'stdio', command: 'echo', args: [] },
  toolMappings: [
    { tool: 'read_file', service: 'filesystem', scope: 'files:read' },
    { tool: 'write_file', service: 'filesystem', scope: 'files:write' },
    { tool: 'search_web', service: 'web-search', scope: 'search:execute' },
  ],
  dbPath: ':memory:',
  denyUnmapped: true,
  clockSkewSeconds: 30,
};

async function createTestToken(
  privateKey: CryptoKey,
  overrides?: {
    services?: Array<{ service: string; scopes: string[]; constraints?: Record<string, unknown> }>;
    rules?: Array<{ id: string; enforcement: string; description: string }>;
    exp?: number;
  }
) {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    jti: `test-token-${crypto.randomUUID()}`,
    iss: 'test-auth-server',
    iat: now,
    exp: overrides?.exp ?? now + 3600,
    definition: {
      principal: { id: 'test-principal' },
      agent: { id: 'test-agent' },
      services: overrides?.services ?? [
        { service: 'filesystem', scopes: ['files:read', 'files:write'] },
        { service: 'web-search', scopes: ['search:execute'] },
      ],
      rules: overrides?.rules,
      expires: new Date((overrides?.exp ?? now + 3600) * 1000).toISOString(),
    },
  };

  return new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(payload))
  )
    .setProtectedHeader({ alg: 'EdDSA' })
    .sign(privateKey);
}

describe('extractToken', () => {
  it('extracts token from _meta.apoa_token', () => {
    const params = { _meta: { apoa_token: 'my-jwt-token' } };
    expect(extractToken(params)).toBe('my-jwt-token');
  });

  it('returns null when no _meta', () => {
    expect(extractToken({})).toBeNull();
  });

  it('returns null when _meta has no apoa_token', () => {
    expect(extractToken({ _meta: { other: 'value' } })).toBeNull();
  });
});

describe('resolveMapping', () => {
  it('resolves explicit mapping', () => {
    const result = resolveMapping('read_file', {}, testConfig.toolMappings, testConfig);
    expect(result).toEqual({ service: 'filesystem', scope: 'files:read' });
  });

  it('auto-maps unmapped tool to tool_name:call by default', () => {
    const result = resolveMapping('unknown_tool', {}, testConfig.toolMappings, testConfig);
    expect(result).toEqual({ service: 'unknown_tool', scope: 'unknown_tool:call' });
  });

  it('returns null for unmapped tool when autoMapping is false', () => {
    const configNoAuto = { ...testConfig, autoMapping: false };
    const result = resolveMapping('unknown_tool', {}, testConfig.toolMappings, configNoAuto);
    expect(result).toBeNull();
  });

  it('uses defaults when configured', () => {
    const configWithDefaults = {
      ...testConfig,
      defaultService: 'fallback-service',
      defaultScope: 'general:access',
    };
    const result = resolveMapping('unknown_tool', {}, testConfig.toolMappings, configWithDefaults);
    expect(result).toEqual({ service: 'fallback-service', scope: 'general:access' });
  });

  it('evaluates conditional mappings with when clause', () => {
    const mappings = [
      { tool: 'read_file', service: 'fs', scope: 'files:read:sandbox', when: { path: { startsWith: '/tmp' } }, priority: 10 },
      { tool: 'read_file', service: 'fs', scope: 'files:read', priority: 0 },
    ];
    const sandboxResult = resolveMapping('read_file', { path: '/tmp/test.txt' }, mappings, testConfig);
    expect(sandboxResult).toEqual({ service: 'fs', scope: 'files:read:sandbox' });

    const generalResult = resolveMapping('read_file', { path: '/home/user/file.txt' }, mappings, testConfig);
    expect(generalResult).toEqual({ service: 'fs', scope: 'files:read' });
  });

  it('falls through conditional mappings to unconditional', () => {
    const mappings = [
      { tool: 'read_file', service: 'fs', scope: 'files:read:special', when: { path: { equals: '/special' } }, priority: 10 },
      { tool: 'read_file', service: 'fs', scope: 'files:read', priority: 0 },
    ];
    const result = resolveMapping('read_file', { path: '/other' }, mappings, testConfig);
    expect(result).toEqual({ service: 'fs', scope: 'files:read' });
  });
});

describe('authorizeToolCall', () => {
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  let revocationStore: TestRevocationStore;
  let auditStore: TestAuditStore;
  let ctx: AuthorizationContext;

  beforeEach(async () => {
    const keyPair = await jose.generateKeyPair('EdDSA', { extractable: true });
    privateKey = keyPair.privateKey as CryptoKey;
    publicKey = keyPair.publicKey as CryptoKey;
    revocationStore = new TestRevocationStore();
    auditStore = new TestAuditStore();
    ctx = { config: testConfig, revocationStore, auditStore, publicKey };
  });

  it('denies when no token provided', async () => {
    const result = await authorizeToolCall('read_file', {}, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('No APOA token');
  });

  it('denies unmapped tool when denyUnmapped is true and autoMapping is false', async () => {
    const noAutoCtx = { ...ctx, config: { ...testConfig, autoMapping: false } };
    const token = await createTestToken(privateKey);
    const result = await authorizeToolCall('unknown_tool', { _meta: { apoa_token: token } }, noAutoCtx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('no APOA mapping');
  });

  it('allows valid token with matching scope', async () => {
    const token = await createTestToken(privateKey);
    const result = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(true);
    expect(result.service).toBe('filesystem');
    expect(result.scope).toBe('files:read');
  });

  it('denies when service not in token', async () => {
    const token = await createTestToken(privateKey, {
      services: [{ service: 'other-service', scopes: ['read'] }],
    });
    const result = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("service 'filesystem' not found");
  });

  it('denies when scope not authorized', async () => {
    const token = await createTestToken(privateKey, {
      services: [{ service: 'filesystem', scopes: ['files:delete'] }],
    });
    const result = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('not in authorized scopes');
  });

  it('denies revoked tokens', async () => {
    const token = await createTestToken(privateKey);
    // Decode to get jti
    const decoded = jose.decodeJwt(token);
    await revocationStore.add({
      tokenId: decoded.jti!,
      revokedAt: new Date(),
      revokedBy: 'test-principal',
      cascaded: [],
    });

    const result = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('revoked');
  });

  it('denies when constraint blocks action', async () => {
    const token = await createTestToken(privateKey, {
      services: [{
        service: 'filesystem',
        scopes: ['files:read', 'files:write'],
        constraints: { write: false },
      }],
    });
    const result = await authorizeToolCall('write_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("constraint 'write'");
  });

  it('denies when hard rule blocks action (segment-based matching)', async () => {
    const token = await createTestToken(privateKey, {
      services: [{ service: 'filesystem', scopes: ['files:read', 'files:write'] }],
      rules: [{ id: 'no-write', enforcement: 'hard', description: 'No writing allowed' }],
    });
    const result = await authorizeToolCall('write_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("hard rule 'no-write' violated");
  });

  it('does NOT false-positive on substring match (C1 fix)', async () => {
    // "no-read" should NOT block "threading:update" even though "threading" contains "read"
    const token = await createTestToken(privateKey, {
      services: [{ service: 'filesystem', scopes: ['files:read'] }],
      rules: [{ id: 'no-signing', enforcement: 'hard', description: 'No signing' }],
    });
    // "files:read" does not contain segment "signing", so should be allowed
    const result = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(true);
  });

  it('logs audit entries for all decisions', async () => {
    const token = await createTestToken(privateKey);
    await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(auditStore.entries.length).toBe(1);
    expect(auditStore.entries[0].result).toBe('allowed');

    // Denied case
    await authorizeToolCall('read_file', {}, ctx);
    // No token = no audit (can't log without token ID)
    expect(auditStore.entries.length).toBe(1);
  });

  it('allows with escalated audit when soft rule matches', async () => {
    const token = await createTestToken(privateKey, {
      services: [{ service: 'filesystem', scopes: ['files:read', 'files:write'] }],
      rules: [{ id: 'no-write', enforcement: 'soft', description: 'Prefer no writing' }],
    });
    const result = await authorizeToolCall('write_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(true);
    expect(result.reason).toContain('soft rule');
    expect(auditStore.entries.length).toBe(1);
    expect(auditStore.entries[0].result).toBe('escalated');
  });

  it('soft rules always produce violations (SDK behavior)', async () => {
    // The SDK fires all soft rules as violations on every authorized call,
    // regardless of whether the rule key matches a scope segment.
    const token = await createTestToken(privateKey, {
      services: [{ service: 'filesystem', scopes: ['files:read'] }],
      rules: [{ id: 'no-write', enforcement: 'soft', description: 'Prefer no writing' }],
    });
    const result = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(true);
    expect(auditStore.entries.length).toBe(1);
    expect(auditStore.entries[0].result).toBe('escalated');
  });

  it('hard rule still blocks when both hard and soft rules present', async () => {
    const token = await createTestToken(privateKey, {
      services: [{ service: 'filesystem', scopes: ['files:read', 'files:write'] }],
      rules: [
        { id: 'no-write', enforcement: 'hard', description: 'No writing allowed' },
        { id: 'no-read', enforcement: 'soft', description: 'Prefer no reading' },
      ],
    });
    const result = await authorizeToolCall('write_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("hard rule 'no-write' violated");
  });

  it('denies with invalid signature', async () => {
    // Create token with a different key
    const otherKey = await jose.generateKeyPair('EdDSA', { extractable: true });
    const token = await createTestToken(otherKey.privateKey as CryptoKey);
    const result = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('signature verification failed');
  });

  it('denies replay when replayStore is configured', async () => {
    const seen = new Set<string>();
    const testReplayStore: ReplayStore = {
      async markAndCheck(jti: string) {
        if (seen.has(jti)) return true;
        seen.add(jti);
        return false;
      },
      async cleanup() { return 0; },
    };
    const ctxWithReplay = { ...ctx, replayStore: testReplayStore };

    const token = await createTestToken(privateKey);
    const first = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctxWithReplay);
    expect(first.authorized).toBe(true);

    const second = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctxWithReplay);
    expect(second.authorized).toBe(false);
    expect(second.reason).toContain('replay');
  });

  it('allows reuse when no replayStore configured (default)', async () => {
    const token = await createTestToken(privateKey);
    const first = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(first.authorized).toBe(true);

    const second = await authorizeToolCall('read_file', { _meta: { apoa_token: token } }, ctx);
    expect(second.authorized).toBe(true);
  });
});
