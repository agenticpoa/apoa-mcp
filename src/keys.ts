import * as jose from 'jose';
import { readFileSync } from 'node:fs';
import type { GatewayConfig } from './config/schema.js';

/** A key or JWKS function that jose.jwtVerify accepts */
export type KeyResolver = CryptoKey | Uint8Array | ReturnType<typeof jose.createRemoteJWKSet>;

/** Resolves a KeyResolver by issuer string */
export type IssuerKeyResolver = (issuer: string) => Promise<KeyResolver | undefined>;

/**
 * Load a single key from a source config (jwks or file).
 */
async function loadSingleKey(
  source: { type: 'jwks'; url: string } | { type: 'file'; path: string }
): Promise<KeyResolver> {
  if (source.type === 'jwks') {
    return jose.createRemoteJWKSet(new URL(source.url));
  }

  const pem = readFileSync(source.path, 'utf-8');

  if (pem.includes('BEGIN PUBLIC KEY')) {
    // Try ES256 first (most common for APOA), fall back to RS256
    try {
      return await jose.importSPKI(pem, 'ES256');
    } catch {
      return await jose.importSPKI(pem, 'RS256');
    }
  }

  // Try JWK format
  try {
    const jwk = JSON.parse(pem);
    return await jose.importJWK(jwk) as CryptoKey;
  } catch {
    throw new Error(
      `Unrecognized key format in ${source.path}. Expected PEM (SPKI) or JWK.`
    );
  }
}

/**
 * Load the public key for APOA token verification.
 * Supports three modes:
 *   - JWKS URL: fetches keys from a remote JWKS endpoint
 *   - Local file: reads a PEM-encoded public key from disk
 *   - Per-issuer: maps issuer strings to individual key sources
 */
export async function loadPublicKey(
  config: GatewayConfig
): Promise<KeyResolver | undefined> {
  const source = config.publicKeySource;
  if (!source) return undefined;

  if (source.type === 'per-issuer') {
    // Per-issuer keys are handled via loadIssuerKeys
    return source.default ? await loadSingleKey(source.default) : undefined;
  }

  console.error(`[keys] Loading public key from ${source.type === 'jwks' ? source.url : source.path}`);
  return loadSingleKey(source);
}

/**
 * Load per-issuer key resolver from config.
 * Returns undefined if the config doesn't use per-issuer mode.
 */
export async function loadIssuerKeys(
  config: GatewayConfig
): Promise<IssuerKeyResolver | undefined> {
  const source = config.publicKeySource;
  if (!source || source.type !== 'per-issuer') return undefined;

  const keyMap = new Map<string, KeyResolver>();
  for (const [issuer, keySource] of Object.entries(source.issuers)) {
    console.error(`[keys] Loading key for issuer '${issuer}'`);
    keyMap.set(issuer, await loadSingleKey(keySource));
  }

  let defaultKey: KeyResolver | undefined;
  if (source.default) {
    console.error('[keys] Loading default issuer key');
    defaultKey = await loadSingleKey(source.default);
  }

  return async (issuer: string) => keyMap.get(issuer) ?? defaultKey;
}
