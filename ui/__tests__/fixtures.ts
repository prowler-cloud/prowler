/**
 * Vitest fixtures shared by the browser-mode integration tests.
 *
 * `seedRuntimeConfig` writes the runtime-config data island (`<script
 * type="application/json">` in <head>) that `isCloud()` and the other runtime
 * readers parse in the browser. There is no Next.js server in browser mode to
 * render it, so tests seed it themselves; a test passes only the keys it cares
 * about and the production reader (`pickConfig`) fills the rest with defaults.
 *
 * The fixture is `auto`, so every test gets a default island (`cloudEnabled:
 * true`) without opting in, and the island is removed on teardown so nothing
 * leaks to the next test. Destructure `seedRuntimeConfig` to override — call it
 * before mounting, since the readers are uncached and read at render time. An
 * override merges onto the default island, so seeding one key does not silently
 * revert the others to the reader's fallback.
 */
import { test as base } from "vitest";

import {
  RUNTIME_CONFIG_SCRIPT_ID,
  type RuntimePublicConfig,
} from "@/lib/runtime-config.shared";

export type SeedRuntimeConfig = (partial: Partial<RuntimePublicConfig>) => void;

/** Baseline island every test starts from; overrides merge onto it. */
const DEFAULT_CONFIG: Partial<RuntimePublicConfig> = { cloudEnabled: true };

const writeIsland: SeedRuntimeConfig = (partial) => {
  document.getElementById(RUNTIME_CONFIG_SCRIPT_ID)?.remove();
  const island = document.createElement("script");
  island.id = RUNTIME_CONFIG_SCRIPT_ID;
  island.type = "application/json";
  island.textContent = JSON.stringify({ ...DEFAULT_CONFIG, ...partial });
  document.head.append(island);
};

const removeIsland = (): void =>
  document.getElementById(RUNTIME_CONFIG_SCRIPT_ID)?.remove();

interface Fixtures {
  seedRuntimeConfig: SeedRuntimeConfig;
}

export const test = base.extend<Fixtures>({
  seedRuntimeConfig: [
    async ({}, use) => {
      writeIsland({});
      await use(writeIsland);
      removeIsland();
    },
    { auto: true },
  ],
});

export const it = test;
