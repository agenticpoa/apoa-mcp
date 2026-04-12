import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { unlinkSync, existsSync } from 'node:fs';
import { SqliteRevocationStore } from '../src/stores/sqlite-revocation.js';
import { SqliteAuditStore } from '../src/stores/sqlite-audit.js';
import { SqliteReplayStore } from '../src/stores/sqlite-replay.js';

const TEST_DB = './test-stores.db';

function cleanup() {
  for (const suffix of ['', '-wal', '-shm']) {
    const path = TEST_DB + suffix;
    if (existsSync(path)) unlinkSync(path);
  }
}

describe('SqliteRevocationStore', () => {
  let store: SqliteRevocationStore;

  beforeEach(() => {
    cleanup();
    store = new SqliteRevocationStore(TEST_DB);
  });

  afterEach(() => {
    store.close();
    cleanup();
  });

  it('stores and retrieves revocation records', async () => {
    await store.add({
      tokenId: 'token-1',
      revokedAt: new Date('2026-03-29T10:00:00Z'),
      revokedBy: 'principal-1',
      reason: 'test revocation',
      cascaded: ['child-1', 'child-2'],
    });

    const record = await store.check('token-1');
    expect(record).not.toBeNull();
    expect(record!.tokenId).toBe('token-1');
    expect(record!.revokedBy).toBe('principal-1');
    expect(record!.reason).toBe('test revocation');
    expect(record!.cascaded).toEqual(['child-1', 'child-2']);
  });

  it('returns null for non-revoked tokens', async () => {
    const record = await store.check('nonexistent');
    expect(record).toBeNull();
  });

  it('lists revocations by principal', async () => {
    await store.add({
      tokenId: 'token-1',
      revokedAt: new Date(),
      revokedBy: 'principal-1',
      cascaded: [],
    });
    await store.add({
      tokenId: 'token-2',
      revokedAt: new Date(),
      revokedBy: 'principal-1',
      cascaded: [],
    });
    await store.add({
      tokenId: 'token-3',
      revokedAt: new Date(),
      revokedBy: 'principal-2',
      cascaded: [],
    });

    const p1Records = await store.list('principal-1');
    expect(p1Records.length).toBe(2);

    const p2Records = await store.list('principal-2');
    expect(p2Records.length).toBe(1);
  });

  it('checkAny returns first match from multiple token IDs', async () => {
    await store.add({
      tokenId: 'token-revoked',
      revokedAt: new Date(),
      revokedBy: 'principal-1',
      cascaded: [],
    });

    const found = await store.checkAny(['token-not-revoked', 'token-revoked', 'another']);
    expect(found).not.toBeNull();
    expect(found!.tokenId).toBe('token-revoked');

    const notFound = await store.checkAny(['nope-1', 'nope-2']);
    expect(notFound).toBeNull();

    const empty = await store.checkAny([]);
    expect(empty).toBeNull();
  });

  it('survives close and reopen', async () => {
    await store.add({
      tokenId: 'persistent-token',
      revokedAt: new Date('2026-03-29T10:00:00Z'),
      revokedBy: 'principal-1',
      cascaded: [],
    });
    store.close();

    const store2 = new SqliteRevocationStore(TEST_DB);
    const record = await store2.check('persistent-token');
    expect(record).not.toBeNull();
    expect(record!.tokenId).toBe('persistent-token');
    store2.close();
  });
});

describe('SqliteAuditStore', () => {
  let store: SqliteAuditStore;

  beforeEach(() => {
    cleanup();
    store = new SqliteAuditStore(TEST_DB);
  });

  afterEach(() => {
    store.close();
    cleanup();
  });

  it('appends and queries entries by token', async () => {
    await store.append({
      tokenId: 'token-1',
      timestamp: new Date('2026-03-29T10:00:00Z'),
      action: 'files:read',
      service: 'filesystem',
      result: 'allowed',
    });
    await store.append({
      tokenId: 'token-1',
      timestamp: new Date('2026-03-29T10:01:00Z'),
      action: 'files:write',
      service: 'filesystem',
      result: 'denied',
      details: { reason: 'scope violation' },
    });

    const entries = await store.query('token-1');
    expect(entries.length).toBe(2);
    expect(entries[0].action).toBe('files:read');
    expect(entries[1].action).toBe('files:write');
    expect(entries[1].details).toEqual({ reason: 'scope violation' });
  });

  it('queries by service', async () => {
    await store.append({
      tokenId: 'token-1',
      timestamp: new Date(),
      action: 'files:read',
      service: 'filesystem',
      result: 'allowed',
    });
    await store.append({
      tokenId: 'token-2',
      timestamp: new Date(),
      action: 'search:execute',
      service: 'web-search',
      result: 'allowed',
    });

    const fsEntries = await store.queryByService('filesystem');
    expect(fsEntries.length).toBe(1);

    const webEntries = await store.queryByService('web-search');
    expect(webEntries.length).toBe(1);
  });

  it('verifies integrity of audit chain', async () => {
    await store.append({
      tokenId: 'token-1',
      timestamp: new Date('2026-03-29T10:00:00Z'),
      action: 'files:read',
      service: 'filesystem',
      result: 'allowed',
    });
    await store.append({
      tokenId: 'token-1',
      timestamp: new Date('2026-03-29T10:01:00Z'),
      action: 'files:write',
      service: 'filesystem',
      result: 'denied',
    });

    const integrity = await store.verifyIntegrity();
    expect(integrity.valid).toBe(true);
  });

  it('applies query filters (timestamp, result)', async () => {
    await store.append({
      tokenId: 'token-1',
      timestamp: new Date('2026-03-29T10:00:00Z'),
      action: 'files:read',
      service: 'filesystem',
      result: 'allowed',
    });
    await store.append({
      tokenId: 'token-1',
      timestamp: new Date('2026-03-29T12:00:00Z'),
      action: 'files:write',
      service: 'filesystem',
      result: 'denied',
    });

    const filtered = await store.query('token-1', {
      result: 'denied',
    });
    expect(filtered.length).toBe(1);
    expect(filtered[0].action).toBe('files:write');
  });
});

describe('SqliteReplayStore', () => {
  let store: SqliteReplayStore;

  beforeEach(() => {
    cleanup();
    store = new SqliteReplayStore(TEST_DB);
  });

  afterEach(() => {
    store.close();
    cleanup();
  });

  it('returns false on first use, true on replay', async () => {
    const expiry = new Date(Date.now() + 3600_000);
    const first = await store.markAndCheck('jti-1', expiry);
    expect(first).toBe(false);

    const second = await store.markAndCheck('jti-1', expiry);
    expect(second).toBe(true);
  });

  it('tracks different JTIs independently', async () => {
    const expiry = new Date(Date.now() + 3600_000);
    expect(await store.markAndCheck('jti-a', expiry)).toBe(false);
    expect(await store.markAndCheck('jti-b', expiry)).toBe(false);
    expect(await store.markAndCheck('jti-a', expiry)).toBe(true);
  });

  it('cleans up expired entries', async () => {
    const pastExpiry = new Date(Date.now() - 60_000);
    await store.markAndCheck('expired-jti', pastExpiry);

    const purged = await store.cleanup();
    expect(purged).toBe(1);

    // After cleanup, the same jti can be used again
    const result = await store.markAndCheck('expired-jti', new Date(Date.now() + 3600_000));
    expect(result).toBe(false);
  });
});
