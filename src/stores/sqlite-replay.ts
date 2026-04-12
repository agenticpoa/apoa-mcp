import Database from 'better-sqlite3';
import type { ReplayStore } from './types.js';

/**
 * SQLite-backed JTI replay protection store.
 * Tracks seen token IDs and rejects duplicates within their validity window.
 * Runs lazy cleanup every CLEANUP_INTERVAL calls.
 */
const CLEANUP_INTERVAL = 100;

export class SqliteReplayStore implements ReplayStore {
  private db: Database.Database;
  private callCount = 0;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS seen_jtis (
        jti TEXT PRIMARY KEY,
        expires_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_seen_jtis_expires ON seen_jtis(expires_at);
    `);
  }

  async markAndCheck(jti: string, expiresAt: Date): Promise<boolean> {
    this.callCount++;
    if (this.callCount % CLEANUP_INTERVAL === 0) {
      await this.cleanup();
    }

    const result = this.db.prepare(
      'INSERT OR IGNORE INTO seen_jtis (jti, expires_at) VALUES (?, ?)'
    ).run(jti, expiresAt.toISOString());

    // If changes === 0, the row already existed (replay)
    return result.changes === 0;
  }

  async cleanup(): Promise<number> {
    const now = new Date().toISOString();
    const result = this.db.prepare(
      'DELETE FROM seen_jtis WHERE expires_at < ?'
    ).run(now);
    return result.changes;
  }

  close(): void {
    this.db.close();
  }
}
