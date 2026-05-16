import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as jose from 'jose';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { GatewayConfig } from '../src/config/schema.js';
import type { RevocationStore, AuditStore, AuditEntry, RevocationRecord } from '../src/stores/types.js';
import { authorizeToolCall, type AuthorizationContext } from '../src/middleware/authorize.js';

// --- Test helpers ---

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
    { tool: 'delete_file', service: 'filesystem', scope: 'files:delete' },
  ],
  dbPath: ':memory:',
  denyUnmapped: true,
  clockSkewSeconds: 30,
};

async function makeKeyPair() {
  return jose.generateKeyPair('ES256');
}

async function createToken(
  privateKey: CryptoKey,
  opts: {
    jti?: string;
    iss?: string;
    services?: Array<{ service: string; scopes: string[]; constraints?: Record<string, unknown> }>;
    rules?: Array<{ id: string; enforcement: string; description: string }>;
    exp?: number;
    parentToken?: string;
    delegationChain?: unknown[];
  } = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    sub: 'agent:test-agent',
    iss: opts.iss ?? 'principal:test-user',
    jti: opts.jti ?? `tok_${crypto.randomUUID()}`,
    definition: {
      services: opts.services ?? [
        { service: 'filesystem', scopes: ['files:read', 'files:write'] },
      ],
      rules: opts.rules,
      parentToken: opts.parentToken,
      delegationChain: opts.delegationChain,
    },
  })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt(now)
    .setExpirationTime(opts.exp ?? now + 3600)
    .sign(privateKey);
}

// --- Integration tests ---

describe('Gateway integration', () => {
  let keys: Awaited<ReturnType<typeof makeKeyPair>>;
  let revocationStore: TestRevocationStore;
  let auditStore: TestAuditStore;

  beforeEach(async () => {
    keys = await makeKeyPair();
    revocationStore = new TestRevocationStore();
    auditStore = new TestAuditStore();
  });

  describe('full authorization flow', () => {
    it('allows authorized tool call and logs audit entry', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(true);
      expect(decision.service).toBe('filesystem');
      expect(decision.scope).toBe('files:read');

      // Audit entry was recorded
      expect(auditStore.entries).toHaveLength(1);
      expect(auditStore.entries[0].result).toBe('allowed');
      expect(auditStore.entries[0].service).toBe('filesystem');
    });

    it('denies tool call with wrong scope', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'write_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('scope');
      expect(auditStore.entries[0].result).toBe('denied');
    });

    it('denies revoked tokens', async () => {
      const tokenId = 'tok_revoked_123';
      const token = await createToken(keys.privateKey, {
        jti: tokenId,
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      await revocationStore.add({
        tokenId,
        revokedAt: new Date(),
        revokedBy: 'principal:admin',
        reason: 'Compromised',
        cascaded: [],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('revoked');
    });

    it('denies expired tokens', async () => {
      const token = await createToken(keys.privateKey, {
        exp: Math.floor(Date.now() / 1000) - 120,
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      // jose.jwtVerify throws on expired tokens before we even check
      expect(decision.reason).toContain('verification failed');
    });

    it('enforces hard rules', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:delete'] }],
        rules: [
          { id: 'no-delete', enforcement: 'hard', description: 'Cannot delete files' },
        ],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'delete_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('hard rule');
      expect(decision.reason).toContain('no-delete');
    });

    it('enforces constraints', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{
          service: 'filesystem',
          scopes: ['files:write'],
          constraints: { write: false },
        }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'write_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain("constraint 'write'");
    });

    it('denies unmapped tools when autoMapping is false and denyUnmapped is true', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['*'] }],
      });

      const ctx: AuthorizationContext = {
        config: { ...testConfig, autoMapping: false },
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'unknown_tool',
        { _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('no APOA mapping');
    });

    it('auto-maps unmapped tools to tool_name:call', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'unknown_tool', scopes: ['unknown_tool:call'] }],
      });

      const ctx: AuthorizationContext = {
        config: { ...testConfig, denyUnmapped: false },
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'unknown_tool',
        { _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(true);
    });

    it('allows with escalated audit when soft rule triggers', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:write'] }],
        rules: [
          { id: 'no-write', enforcement: 'soft', description: 'Prefer read-only' },
        ],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'write_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(true);
      expect(decision.reason).toContain('soft rule');
      expect(auditStore.entries[0].result).toBe('escalated');
    });

    it('denies tokens signed with wrong key', async () => {
      const wrongKeys = await makeKeyPair();
      const token = await createToken(wrongKeys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey, // different from signing key
      };

      const decision = await authorizeToolCall(
        'read_file',
        { path: '/tmp/test.txt', _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('verification failed');
    });

    it('denies when no token is provided', async () => {
      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { path: '/tmp/test.txt' },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('No APOA token');
    });
  });

  describe('multi-service delegation', () => {
    it('authorizes across multiple services in one token', async () => {
      const token = await createToken(keys.privateKey, {
        services: [
          { service: 'filesystem', scopes: ['files:read', 'files:write'] },
          { service: 'web-search', scopes: ['search:execute'] },
        ],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const readDecision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      const searchDecision = await authorizeToolCall(
        'search_web',
        { _meta: { apoa_token: token } },
        ctx
      );

      expect(readDecision.authorized).toBe(true);
      expect(searchDecision.authorized).toBe(true);
      expect(auditStore.entries).toHaveLength(2);
    });
  });

  describe('delegation chain verification', () => {
    it('allows valid 2-level chain with scope narrowing', async () => {
      const now = Math.floor(Date.now() / 1000);
      const parentExp = now + 7200;

      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
        exp: now + 3600,
        delegationChain: [{
          parentTokenId: 'parent-tok-1',
          parentIssuer: 'principal:root',
          parentServices: [{ service: 'filesystem', scopes: ['files:read', 'files:write'] }],
          parentExpiry: parentExp,
        }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(true);
    });

    it('denies when child has broader scope than parent', async () => {
      const now = Math.floor(Date.now() / 1000);

      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read', 'files:write'] }],
        exp: now + 3600,
        delegationChain: [{
          parentTokenId: 'parent-tok-2',
          parentIssuer: 'principal:root',
          parentServices: [{ service: 'filesystem', scopes: ['files:read'] }],
          parentExpiry: now + 7200,
        }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('Delegation chain');
      expect(decision.reason).toContain('not covered by parent');
    });

    it('denies when child expiry exceeds parent', async () => {
      const now = Math.floor(Date.now() / 1000);

      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
        exp: now + 7200, // child lives longer
        delegationChain: [{
          parentTokenId: 'parent-tok-3',
          parentIssuer: 'principal:root',
          parentServices: [{ service: 'filesystem', scopes: ['files:read'] }],
          parentExpiry: now + 3600, // parent expires sooner
        }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('expiry');
    });

    it('denies when chain depth exceeds maximum', async () => {
      const now = Math.floor(Date.now() / 1000);
      const configWithLowDepth = { ...testConfig, maxDelegationDepth: 1 };

      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
        exp: now + 3600,
        delegationChain: [
          {
            parentTokenId: 'root-tok',
            parentIssuer: 'principal:root',
            parentServices: [{ service: 'filesystem', scopes: ['files:*'] }],
            parentExpiry: now + 7200,
          },
          {
            parentTokenId: 'mid-tok',
            parentIssuer: 'principal:mid',
            parentServices: [{ service: 'filesystem', scopes: ['files:read', 'files:write'] }],
            parentExpiry: now + 7200,
          },
        ],
      });

      const ctx: AuthorizationContext = {
        config: configWithLowDepth,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('depth');
    });

    it('denies child when parent token is revoked (cascade revocation)', async () => {
      const now = Math.floor(Date.now() / 1000);

      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
        exp: now + 3600,
        delegationChain: [{
          parentTokenId: 'revoked-parent-tok',
          parentIssuer: 'principal:root',
          parentServices: [{ service: 'filesystem', scopes: ['files:*'] }],
          parentExpiry: now + 7200,
        }],
      });

      // Revoke the parent
      await revocationStore.add({
        tokenId: 'revoked-parent-tok',
        revokedAt: new Date(),
        revokedBy: 'principal:admin',
        reason: 'Compromised parent',
        cascaded: [],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('revoked');
      expect(decision.reason).toContain('ancestor');
    });

    it('denies child when canonical parentToken is revoked', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
        parentToken: 'canonical-parent-tok',
      });

      await revocationStore.add({
        tokenId: 'canonical-parent-tok',
        revokedAt: new Date(),
        revokedBy: 'principal:admin',
        reason: 'Revoked parent',
        cascaded: [],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );

      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('revoked');
      expect(decision.reason).toContain('ancestor');
    });

    it('allows tokens without delegation chain (backward compat)', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(true);
    });

    it('denies when child loosens parent constraint', async () => {
      const now = Math.floor(Date.now() / 1000);

      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
        exp: now + 3600,
        delegationChain: [{
          parentTokenId: 'parent-tok-constrained',
          parentIssuer: 'principal:root',
          parentServices: [{
            service: 'filesystem',
            scopes: ['files:read', 'files:write'],
            constraints: { write: false },
          }],
          parentExpiry: now + 7200,
        }],
      });

      // The leaf has no constraints - it dropped the parent's write:false
      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('constraint');
    });
  });

  describe('per-issuer key resolution', () => {
    it('verifies tokens from different issuers with their own keys', async () => {
      const aliceKeys = await makeKeyPair();
      const bobKeys = await makeKeyPair();

      const aliceToken = await createToken(aliceKeys.privateKey, {
        iss: 'principal:alice',
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });
      const bobToken = await createToken(bobKeys.privateKey, {
        iss: 'principal:bob',
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const issuerKeys = async (issuer: string) => {
        if (issuer === 'principal:alice') return aliceKeys.publicKey;
        if (issuer === 'principal:bob') return bobKeys.publicKey;
        return undefined;
      };

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        issuerKeys,
      };

      const aliceDecision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: aliceToken } },
        ctx
      );
      expect(aliceDecision.authorized).toBe(true);

      const bobDecision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: bobToken } },
        ctx
      );
      expect(bobDecision.authorized).toBe(true);
    });

    it('falls back to default publicKey when issuer not found', async () => {
      const issuerKeys = async () => undefined;

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
        issuerKeys,
      };

      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(true);
    });

    it('denies when issuer not found and no default key', async () => {
      const wrongKeys = await makeKeyPair();
      const issuerKeys = async () => undefined;

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        // no publicKey fallback
        issuerKeys,
      };

      const token = await createToken(wrongKeys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:read'] }],
      });

      const decision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      expect(decision.authorized).toBe(false);
      expect(decision.reason).toContain('No public key');
    });
  });

  describe('wildcard scope matching', () => {
    it('matches wildcard scope patterns', async () => {
      const token = await createToken(keys.privateKey, {
        services: [{ service: 'filesystem', scopes: ['files:*'] }],
      });

      const ctx: AuthorizationContext = {
        config: testConfig,
        revocationStore,
        auditStore,
        publicKey: keys.publicKey,
      };

      const readDecision = await authorizeToolCall(
        'read_file',
        { _meta: { apoa_token: token } },
        ctx
      );
      const writeDecision = await authorizeToolCall(
        'write_file',
        { _meta: { apoa_token: token } },
        ctx
      );

      expect(readDecision.authorized).toBe(true);
      expect(writeDecision.authorized).toBe(true);
    });
  });
});
