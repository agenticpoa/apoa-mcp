import Database from 'better-sqlite3';
import type { AuditEntry, AuditQueryOptions, AuditStore } from './types.js';

/**
 * SQLite-backed persistent audit store.
 * Append-only with hash chaining for tamper evidence.
 * Each entry includes a SHA-256 hash of the previous entry,
 * creating an integrity chain that detects modification or deletion.
 */
export class SqliteAuditStore implements AuditStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        service TEXT NOT NULL,
        result TEXT NOT NULL CHECK(result IN ('allowed', 'denied', 'escalated')),
        details TEXT,
        url TEXT,
        screenshot_ref TEXT,
        access_mode TEXT,
        prev_hash TEXT,
        entry_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_token_id ON audit_entries(token_id);
      CREATE INDEX IF NOT EXISTS idx_audit_service ON audit_entries(service);
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
    `);
  }

  async append(entry: AuditEntry): Promise<void> {
    const lastRow = this.db.prepare(
      'SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1'
    ).get() as { entry_hash: string } | undefined;

    const prevHash = lastRow?.entry_hash ?? null;
    const entryData = JSON.stringify({
      tokenId: entry.tokenId,
      timestamp: entry.timestamp.toISOString(),
      action: entry.action,
      service: entry.service,
      result: entry.result,
      details: entry.details,
      prevHash,
    });

    const entryHash = await hashString(entryData);

    this.db.prepare(`
      INSERT INTO audit_entries (token_id, timestamp, action, service, result, details, url, screenshot_ref, access_mode, prev_hash, entry_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.tokenId,
      entry.timestamp.toISOString(),
      entry.action,
      entry.service,
      entry.result,
      entry.details ? JSON.stringify(entry.details) : null,
      entry.url ?? null,
      entry.screenshotRef ?? null,
      entry.accessMode ?? null,
      prevHash,
      entryHash
    );
  }

  async query(tokenId: string, options?: AuditQueryOptions): Promise<AuditEntry[]> {
    let sql = 'SELECT * FROM audit_entries WHERE token_id = ?';
    const params: unknown[] = [tokenId];
    sql = applyFilters(sql, params, options);
    const rows = this.db.prepare(sql).all(...params) as SqliteAuditRow[];
    return rows.map(rowToEntry);
  }

  async queryByService(service: string, options?: AuditQueryOptions): Promise<AuditEntry[]> {
    let sql = 'SELECT * FROM audit_entries WHERE service = ?';
    const params: unknown[] = [service];
    sql = applyFilters(sql, params, options);
    const rows = this.db.prepare(sql).all(...params) as SqliteAuditRow[];
    return rows.map(rowToEntry);
  }

  /**
   * Verify the integrity of the audit chain.
   * Returns true if all hashes are valid and the chain is unbroken.
   */
  async verifyIntegrity(): Promise<{ valid: boolean; brokenAt?: number }> {
    const rows = this.db.prepare(
      'SELECT id, token_id, timestamp, action, service, result, details, prev_hash, entry_hash FROM audit_entries ORDER BY id ASC'
    ).all() as SqliteAuditRow[];

    let expectedPrevHash: string | null = null;

    for (const row of rows) {
      if (row.prev_hash !== expectedPrevHash) {
        return { valid: false, brokenAt: row.id };
      }

      const entryData = JSON.stringify({
        tokenId: row.token_id,
        timestamp: row.timestamp,
        action: row.action,
        service: row.service,
        result: row.result,
        details: row.details ? JSON.parse(row.details) : undefined,
        prevHash: row.prev_hash,
      });

      const computed = await hashString(entryData);
      if (computed !== row.entry_hash) {
        return { valid: false, brokenAt: row.id };
      }

      expectedPrevHash = row.entry_hash;
    }

    return { valid: true };
  }

  close(): void {
    this.db.close();
  }
}

interface SqliteAuditRow {
  id: number;
  token_id: string;
  timestamp: string;
  action: string;
  service: string;
  result: string;
  details: string | null;
  url: string | null;
  screenshot_ref: string | null;
  access_mode: string | null;
  prev_hash: string | null;
  entry_hash: string;
}

function rowToEntry(row: SqliteAuditRow): AuditEntry {
  return {
    tokenId: row.token_id,
    timestamp: new Date(row.timestamp),
    action: row.action,
    service: row.service,
    result: row.result as 'allowed' | 'denied' | 'escalated',
    details: row.details ? JSON.parse(row.details) : undefined,
    url: row.url ?? undefined,
    screenshotRef: row.screenshot_ref ?? undefined,
    accessMode: row.access_mode as 'api' | 'browser' | undefined,
  };
}

function applyFilters(sql: string, params: unknown[], options?: AuditQueryOptions): string {
  if (options?.from) {
    sql += ' AND timestamp >= ?';
    params.push(options.from.toISOString());
  }
  if (options?.to) {
    sql += ' AND timestamp <= ?';
    params.push(options.to.toISOString());
  }
  if (options?.action) {
    sql += ' AND action = ?';
    params.push(options.action);
  }
  if (options?.service) {
    sql += ' AND service = ?';
    params.push(options.service);
  }
  if (options?.result) {
    sql += ' AND result = ?';
    params.push(options.result);
  }

  sql += ' ORDER BY id ASC';

  const limit = options?.limit ?? 100;
  const offset = options?.offset ?? 0;
  sql += ' LIMIT ? OFFSET ?';
  params.push(limit, offset);

  return sql;
}

async function hashString(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
