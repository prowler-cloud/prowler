import "server-only";

import { AsyncLocalStorage } from "async_hooks";

/**
 * AsyncLocalStorage instance for storing the access token in the current async context.
 * This enables authentication to flow through MCP tool calls without explicit parameter passing.
 *
 * @remarks This module is server-only as it uses Node.js AsyncLocalStorage
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
