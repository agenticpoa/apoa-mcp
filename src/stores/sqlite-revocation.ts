import Database from 'better-sqlite3';
import type { RevocationRecord, RevocationStore } from './types.js';

/**
 * SQLite-backed persistent revocation store.
 * Survives process restarts. Uses WAL mode for concurrent reads.
 */
export class SqliteRevocationStore implements RevocationStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS revocations (
        token_id TEXT PRIMARY KEY,
        revoked_at TEXT NOT NULL,
        revoked_by TEXT NOT NULL,
        reason TEXT,
        cascaded TEXT NOT NULL DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS idx_revocations_revoked_by ON revocations(revoked_by);
    `);
  }

  async add(record: RevocationRecord): Promise<void> {
    this.db.prepare(`
      INSERT OR REPLACE INTO revocations (token_id, revoked_at, revoked_by, reason, cascaded)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      record.tokenId,
      record.revokedAt.toISOString(),
      record.revokedBy,
      record.reason ?? null,
      JSON.stringify(record.cascaded)
    );
  }

  async check(tokenId: string): Promise<RevocationRecord | null> {
    const row = this.db.prepare(
      'SELECT * FROM revocations WHERE token_id = ?'
    ).get(tokenId) as SqliteRevocationRow | undefined;

    if (!row) return null;
    return rowToRecord(row);
  }

  async checkAny(tokenIds: string[]): Promise<RevocationRecord | null> {
    if (tokenIds.length === 0) return null;
    const placeholders = tokenIds.map(() => '?').join(',');
    const row = this.db.prepare(
      `SELECT * FROM revocations WHERE token_id IN (${placeholders}) LIMIT 1`
    ).get(...tokenIds) as SqliteRevocationRow | undefined;
    return row ? rowToRecord(row) : null;
  }

  async list(principalId: string): Promise<RevocationRecord[]> {
    const rows = this.db.prepare(
      'SELECT * FROM revocations WHERE revoked_by = ?'
    ).all(principalId) as SqliteRevocationRow[];

    return rows.map(rowToRecord);
  }

  close(): void {
    this.db.close();
  }
}

interface SqliteRevocationRow {
  token_id: string;
  revoked_at: string;
  revoked_by: string;
  reason: string | null;
  cascaded: string;
}

function rowToRecord(row: SqliteRevocationRow): RevocationRecord {
  return {
    tokenId: row.token_id,
    revokedAt: new Date(row.revoked_at),
    revokedBy: row.revoked_by,
    reason: row.reason ?? undefined,
    cascaded: JSON.parse(row.cascaded),
  };
}
