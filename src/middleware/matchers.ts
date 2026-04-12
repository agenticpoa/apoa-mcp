/**
 * Argument-aware tool mapping matchers.
 *
 * Evaluates conditions on MCP tool call arguments to select
 * the appropriate scope mapping.
 */

export interface ArgumentMatcher {
  equals?: unknown;
  startsWith?: string;
  endsWith?: string;
  contains?: string;
  matches?: string;
  oneOf?: unknown[];
}

/**
 * Evaluate all argument matchers against tool call arguments.
 * Returns true only if every matcher matches its corresponding argument.
 */
export function evaluateMatchers(
  when: Record<string, ArgumentMatcher>,
  args: Record<string, unknown>
): boolean {
  return Object.entries(when).every(([argName, matcher]) => {
    const value = args[argName];
    return evaluateSingleMatcher(matcher, value);
  });
}

function evaluateSingleMatcher(matcher: ArgumentMatcher, value: unknown): boolean {
  if (matcher.equals !== undefined) {
    return value === matcher.equals;
  }
  if (matcher.startsWith !== undefined && typeof value === 'string') {
    return value.startsWith(matcher.startsWith);
  }
  if (matcher.endsWith !== undefined && typeof value === 'string') {
    return value.endsWith(matcher.endsWith);
  }
  if (matcher.contains !== undefined && typeof value === 'string') {
    return value.includes(matcher.contains);
  }
  if (matcher.matches !== undefined && typeof value === 'string') {
    return new RegExp(matcher.matches).test(value);
  }
  if (matcher.oneOf !== undefined) {
    return matcher.oneOf.includes(value);
  }
  return false;
}
