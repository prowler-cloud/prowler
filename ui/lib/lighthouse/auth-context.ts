import { AsyncLocalStorage } from "async_hooks";

/**
 * AsyncLocalStorage instance for storing the access token in the current async context.
 * This enables authentication to flow through MCP tool calls without explicit parameter passing.
 */
export const authContextStorage = new AsyncLocalStorage<string>();

/**
 * Retrieves the access token from the current async context.
 *
 * @returns The access token if available, null otherwise
 *
 * @example
 * ```typescript
 * const token = getAuthContext();
 * if (token) {
 *   headers.Authorization = `Bearer ${token}`;
 * }
 * ```
 */
export function getAuthContext(): string | null {
  return authContextStorage.getStore() ?? null;
}
