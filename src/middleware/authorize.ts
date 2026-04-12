/**
 * MCP tool call authorization using @apoa/core.
 *
 * Gateway-owned concerns: token extraction, tool mapping, per-issuer keys,
 * replay protection, checkAny revocation, audit logging.
 *
 * SDK-provided concerns: scope matching, constraint checking, rule enforcement,
 * delegation chain verification, token validation.
 */

import * as jose from 'jose';
import {
  matchScope,
  checkScope,
  checkConstraint,
  authorize as apoaAuthorize,
  validateToken,
  verifyChain,
  type APOAToken,
  type ScopeCheckResult,
  type AuthorizationResult as APOAAuthorizationResult,
} from '@apoa/core';
import type { ToolMapping, GatewayConfig } from '../config/schema.js';
import type { RevocationStore, AuditStore, AuditEntry, ReplayStore } from '../stores/types.js';
import type { KeyResolver, IssuerKeyResolver } from '../keys.js';
import { evaluateMatchers } from './matchers.js';

export interface AuthorizationContext {
  config: GatewayConfig;
  revocationStore: RevocationStore;
  auditStore: AuditStore;
  publicKey?: KeyResolver;
  issuerKeys?: IssuerKeyResolver;
  replayStore?: ReplayStore;
}

export interface AuthorizationDecision {
  authorized: boolean;
  reason: string;
  tokenId?: string;
  service?: string;
  scope?: string;
}

/**
 * Extract APOA token from MCP tool call metadata.
 */
export function extractToken(params: Record<string, unknown>): string | null {
  const meta = params._meta as Record<string, unknown> | undefined;
  if (meta?.apoa_token && typeof meta.apoa_token === 'string') {
    return meta.apoa_token;
  }
  return null;
}

/**
 * Resolve the APOA service+scope for an MCP tool call.
 * Evaluates conditional mappings (with `when`) by priority first,
 * then unconditional mappings, then defaults, then auto-mapping.
 */
export function resolveMapping(
  toolName: string,
  params: Record<string, unknown>,
  mappings: ToolMapping[],
  config: GatewayConfig
): { service: string; scope: string } | null {
  const candidates = mappings
    .filter((m) => m.tool === toolName)
    .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));

  for (const mapping of candidates) {
    if (mapping.when) {
      if (evaluateMatchers(mapping.when, params)) {
        return { service: mapping.service, scope: mapping.scope };
      }
    } else {
      return { service: mapping.service, scope: mapping.scope };
    }
  }

  if (config.defaultService && config.defaultScope) {
    return { service: config.defaultService, scope: config.defaultScope };
  }

  // Auto-mapping: tool_name -> tool_name:call
  if (config.autoMapping !== false) {
    return { service: toolName, scope: `${toolName}:call` };
  }

  return null;
}

/**
 * Authorize an MCP tool call against an APOA token.
 *
 * Steps:
 * 1. Extract APOA token from metadata          (gateway-owned)
 * 2. Resolve tool -> service+scope mapping      (gateway-owned)
 * 3. Verify token signature (per-issuer keys)   (gateway-owned + SDK)
 * 4. Check revocation (including ancestors)     (gateway-owned)
 * 5. Check replay protection                    (gateway-owned)
 * 6. Authorize: scope + constraints + rules     (SDK: authorize())
 * 7. Log audit entry                            (gateway-owned)
 */
export async function authorizeToolCall(
  toolName: string,
  params: Record<string, unknown>,
  ctx: AuthorizationContext
): Promise<AuthorizationDecision> {
  // 1. Extract token
  const rawToken = extractToken(params);
  if (!rawToken) {
    return deny('No APOA token provided in tool call metadata (_meta.apoa_token)');
  }

  // 2. Resolve mapping
  const mapping = resolveMapping(toolName, params, ctx.config.toolMappings, ctx.config);
  if (!mapping) {
    if (ctx.config.denyUnmapped) {
      return deny(`Tool '${toolName}' has no APOA mapping and denyUnmapped is enabled`);
    }
    return allow(`Tool '${toolName}' has no mapping but denyUnmapped is disabled`);
  }

  // 3. Verify token signature and decode
  let payload: jose.JWTPayload;
  try {
    let verifyKey: KeyResolver | undefined = ctx.publicKey;

    // Per-issuer key resolution
    if (ctx.issuerKeys) {
      const claims = jose.decodeJwt(rawToken);
      if (claims.iss) {
        const issuerKey = await ctx.issuerKeys(claims.iss);
        if (issuerKey) {
          verifyKey = issuerKey;
        }
      }
    }

    if (!verifyKey) {
      return deny('No public key configured for token verification');
    }
    const { payload: p } = await jose.jwtVerify(rawToken, verifyKey as Parameters<typeof jose.jwtVerify>[1], {
      clockTolerance: ctx.config.clockSkewSeconds,
    });
    payload = p;
  } catch {
    return deny('Token signature verification failed');
  }

  const tokenId = payload.jti;
  if (!tokenId) {
    return deny('Token has no jti claim');
  }

  const definition = payload.definition as Record<string, unknown> | undefined;
  if (!definition) {
    await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', 'No definition in token');
    return deny('Token has no definition claim', tokenId, mapping.service, mapping.scope);
  }

  // 4. Check revocation (including delegation chain ancestors)
  const delegationChain = definition.delegationChain as Array<{ parentTokenId: string }> | undefined;
  const tokenIdsToCheck = [tokenId];
  if (delegationChain) {
    for (const link of delegationChain) {
      tokenIdsToCheck.push(link.parentTokenId);
    }
  }

  const revRecord = ctx.revocationStore.checkAny
    ? await ctx.revocationStore.checkAny(tokenIdsToCheck)
    : await ctx.revocationStore.check(tokenId);

  if (revRecord) {
    const ancestorNote = revRecord.tokenId !== tokenId ? ` (ancestor ${revRecord.tokenId})` : '';
    await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', `Token revoked${ancestorNote}`);
    return deny(
      `Token has been revoked${ancestorNote} (at ${revRecord.revokedAt.toISOString()} by ${revRecord.revokedBy})`,
      tokenId, mapping.service, mapping.scope
    );
  }

  // 5. Replay protection
  if (ctx.replayStore) {
    const expiry = payload.exp
      ? new Date(payload.exp * 1000)
      : new Date(Date.now() + 3600_000);
    const isReplay = await ctx.replayStore.markAndCheck(tokenId, expiry);
    if (isReplay) {
      await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', 'Replay detected');
      return deny('Token jti has already been used (replay)', tokenId, mapping.service, mapping.scope);
    }
  }

  // 5b. Verify delegation chain (if present in token payload)
  const fullDelegationChain = definition.delegationChain as Array<{
    parentTokenId: string;
    parentIssuer: string;
    parentServices: Array<{ service: string; scopes: string[]; constraints?: Record<string, boolean> }>;
    parentExpiry: number;
  }> | undefined;

  if (fullDelegationChain && fullDelegationChain.length > 0) {
    const maxDepth = ctx.config.maxDelegationDepth ?? 5;
    if (fullDelegationChain.length > maxDepth) {
      await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', `Chain depth ${fullDelegationChain.length} exceeds max ${maxDepth}`);
      return deny(`Delegation chain verification failed: Delegation chain depth ${fullDelegationChain.length} exceeds maximum ${maxDepth}`, tokenId, mapping.service, mapping.scope);
    }

    // Verify attenuation: each child must narrow parent scopes/expiry/constraints
    const leafServices = (definition.services as Array<{ service: string; scopes: string[]; constraints?: Record<string, boolean> }>) ?? [];
    const leafExpiry = payload.exp!;

    // Check chain links
    for (let i = 1; i < fullDelegationChain.length; i++) {
      const parent = fullDelegationChain[i - 1];
      const child = fullDelegationChain[i];
      const chainCheck = verifyChainLink(parent.parentServices, parent.parentExpiry, child.parentServices, child.parentExpiry);
      if (!chainCheck.valid) {
        await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', `Delegation chain: ${chainCheck.reason}`);
        return deny(`Delegation chain verification failed: Chain link ${i}: ${chainCheck.reason}`, tokenId, mapping.service, mapping.scope);
      }
    }

    // Verify leaf against last parent
    const lastLink = fullDelegationChain[fullDelegationChain.length - 1];
    const leafCheck = verifyChainLink(lastLink.parentServices, lastLink.parentExpiry, leafServices, leafExpiry);
    if (!leafCheck.valid) {
      await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', `Delegation chain: Leaf token: ${leafCheck.reason}`);
      return deny(`Delegation chain verification failed: Leaf token: ${leafCheck.reason}`, tokenId, mapping.service, mapping.scope);
    }
  }

  // 6. Authorize using @apoa/core: scope + constraints + rules
  //    Build a minimal APOAToken from the JWT payload for SDK consumption
  const services = definition.services as Array<{
    service: string;
    scopes: string[];
    constraints?: Record<string, unknown>;
  }> | undefined;

  if (!services) {
    await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', 'No services in definition');
    return deny('Token definition has no services', tokenId, mapping.service, mapping.scope);
  }

  const apoaToken: APOAToken = {
    jti: tokenId,
    definition: {
      principal: (definition.principal as { id: string }) ?? { id: payload.iss ?? 'unknown' },
      agent: (definition.agent as { id: string }) ?? { id: 'unknown' },
      services: services.map((s) => ({
        service: s.service,
        scopes: s.scopes,
        constraints: s.constraints as Record<string, boolean | number | string | string[]> | undefined,
      })),
      expires: payload.exp ? new Date(payload.exp * 1000) : new Date(),
      rules: definition.rules as Array<{ id: string; description: string; enforcement: 'hard' | 'soft' }> | undefined,
    },
    issuedAt: payload.iat ? new Date(payload.iat * 1000) : new Date(),
    signature: rawToken.split('.')[2],
    issuer: payload.iss ?? '',
    raw: rawToken,
  };

  // SDK handles: scope matching + constraint checking + hard/soft rules
  const result = await apoaAuthorize(apoaToken, mapping.service, mapping.scope);

  if (!result.authorized) {
    await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, 'denied', result.reason ?? 'Authorization denied');
    return deny(result.reason ?? 'Authorization denied', tokenId, mapping.service, mapping.scope);
  }

  // Check for soft rule violations (SDK returns authorized=true with violations)
  const softViolation = result.violations?.[0];
  const auditResult = softViolation ? 'escalated' as const : 'allowed' as const;
  const auditDetails = softViolation ? `Soft rule '${softViolation.ruleId}' triggered` : undefined;
  await logAudit(ctx, tokenId, toolName, mapping.service, mapping.scope, auditResult, auditDetails);

  return {
    authorized: true,
    reason: softViolation
      ? `Authorized with warning: soft rule '${softViolation.ruleId}' triggered for tool '${toolName}' -> ${mapping.service}:${mapping.scope}`
      : `Authorized: tool '${toolName}' -> ${mapping.service}:${mapping.scope}`,
    tokenId,
    service: mapping.service,
    scope: mapping.scope,
  };
}

function deny(reason: string, tokenId?: string, service?: string, scope?: string): AuthorizationDecision {
  return { authorized: false, reason, tokenId, service, scope };
}

function allow(reason: string): AuthorizationDecision {
  return { authorized: true, reason };
}

function verifyChainLink(
  parentServices: Array<{ service: string; scopes: string[]; constraints?: Record<string, boolean> }>,
  parentExpiry: number,
  childServices: Array<{ service: string; scopes: string[]; constraints?: Record<string, boolean> }>,
  childExpiry: number,
): { valid: boolean; reason?: string } {
  // Expiry attenuation
  if (childExpiry > parentExpiry) {
    return { valid: false, reason: 'Child expiry exceeds parent expiry' };
  }

  for (const childSvc of childServices) {
    const parentSvc = parentServices.find(p => p.service === childSvc.service);
    if (!parentSvc) {
      return { valid: false, reason: `Child service '${childSvc.service}' not in parent` };
    }

    // Scope attenuation using SDK's matchScope
    for (const childScope of childSvc.scopes) {
      const covered = parentSvc.scopes.some(ps => matchScope(ps, childScope));
      if (!covered) {
        return { valid: false, reason: `Child scope '${childScope}' in service '${childSvc.service}' not covered by parent scopes [${parentSvc.scopes.join(', ')}]` };
      }
    }

    // Constraint tightening
    if (parentSvc.constraints && childSvc.constraints) {
      for (const [key, parentValue] of Object.entries(parentSvc.constraints)) {
        if (parentValue === false && childSvc.constraints[key] !== false) {
          return { valid: false, reason: `Child loosened constraint '${key}' in service '${childSvc.service}'` };
        }
      }
    } else if (parentSvc.constraints && !childSvc.constraints) {
      const hasFalse = Object.values(parentSvc.constraints).some(v => v === false);
      if (hasFalse) {
        return { valid: false, reason: `Child dropped constraints from service '${childSvc.service}' that parent restricts` };
      }
    }
  }

  return { valid: true };
}

async function logAudit(
  ctx: AuthorizationContext,
  tokenId: string,
  toolName: string,
  service: string,
  scope: string,
  result: 'allowed' | 'denied' | 'escalated',
  details?: string
): Promise<void> {
  const entry: AuditEntry = {
    tokenId,
    timestamp: new Date(),
    action: scope,
    service,
    result,
    details: details ? { tool: toolName, reason: details } : { tool: toolName },
  };
  await ctx.auditStore.append(entry);
}
