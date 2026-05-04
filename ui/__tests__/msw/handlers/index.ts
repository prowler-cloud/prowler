import type { HttpHandler } from "msw";

/**
 * Static handlers shared by every browser test — registered as defaults on
 * the worker. Use this list for endpoints whose response doesn't change
 * across tests (e.g. `/users/me`, `/tenants/current`, health checks).
 *
 * Per-domain dynamic handlers that depend on fixture data live in their own
 * files alongside this index (e.g. `./attack-paths.ts`) and are imported
 * directly by the tests that need them, then wired via
 * `worker.use(...handlersForFixture(fx))`.
 */
export const handlers: HttpHandler[] = [];
