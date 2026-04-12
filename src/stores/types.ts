/**
 * Re-export the APOA store interfaces so gateway code doesn't import from the SDK directly.
 * These match the APOA SDK interfaces exactly.
 */

export type AuditDetailValue = string | number | boolean | null;
export type AccessMode = 'api' | 'browser';

export interface AuditEntry {
  tokenId: string;
  timestamp: Date;
  action: string;
  service: string;
  result: 'allowed' | 'denied' | 'escalated';
  details?: Record<string, AuditDetailValue>;
  url?: string;
  screenshotRef?: string;
  accessMode?: AccessMode;
}

export interface AuditQueryOptions {
  from?: Date;
  to?: Date;
  action?: string;
  service?: string;
  result?: 'allowed' | 'denied' | 'escalated';
  limit?: number;
  offset?: number;
}

export interface AuditStore {
  append(entry: AuditEntry): Promise<void>;
  query(tokenId: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
  queryByService(service: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
}

export interface RevocationRecord {
  tokenId: string;
  revokedAt: Date;
  revokedBy: string;
  reason?: string;
  cascaded: string[];
}

export interface RevocationStore {
  add(record: RevocationRecord): Promise<void>;
  check(tokenId: string): Promise<RevocationRecord | null>;
  /** Check if any of the given token IDs are revoked. Returns the first match. */
  checkAny?(tokenIds: string[]): Promise<RevocationRecord | null>;
  list(principalId: string): Promise<RevocationRecord[]>;
}

export interface ReplayStore {
  /** Returns true if this jti has already been seen (replay). */
  markAndCheck(jti: string, expiresAt: Date): Promise<boolean>;
  /** Purge entries older than their expiry. Returns count of purged entries. */
  cleanup(): Promise<number>;
}
