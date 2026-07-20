/**
 * Shared environment helpers.
 */
import {
  CLOUD_ENABLED_ENV,
  readRuntimeConfigIsland,
} from "@/lib/runtime-config.shared";
import { readBoolEnv } from "@/lib/runtime-env";

/**
 * Whether the UI is running inside a Prowler Cloud deployment.
 *
 * Runtime read, resolved from two sources:
 * - Browser: the runtime public-config island (`cloudEnabled`), rendered in
 *   <head> before any bundle runs, so calling this at module scope is safe.
 * - Without a DOM (RSC, server actions, SSR, edge, Node) and jsdom tests
 *   without an island: `UI_CLOUD_ENABLED`. The island is produced from the
 *   same env var (lib/runtime-config.ts), so SSR and hydration always agree.
 */
export function isCloud(): boolean {
  const islandConfig = readRuntimeConfigIsland();
  if (islandConfig) return islandConfig.cloudEnabled;

  return readBoolEnv(CLOUD_ENABLED_ENV);
}
