import { afterEach, describe, expect, it, vi } from "vitest";

import { RUNTIME_CONFIG_SCRIPT_ID } from "@/lib/runtime-config.shared";

import { isCloud } from "./env";

const writeIsland = (content: Record<string, unknown> | string) => {
  const el = document.createElement("script");
  el.id = RUNTIME_CONFIG_SCRIPT_ID;
  el.type = "application/json";
  el.textContent =
    typeof content === "string" ? content : JSON.stringify(content);
  document.head.appendChild(el);
};

describe("isCloud", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    document.head.innerHTML = "";
  });

  describe("without an island (server / jsdom env fallback)", () => {
    it('returns true when UI_CLOUD_ENABLED is "true"', () => {
      vi.stubEnv("UI_CLOUD_ENABLED", "true");
      expect(isCloud()).toBe(true);
    });

    it('returns false when UI_CLOUD_ENABLED is "false"', () => {
      vi.stubEnv("UI_CLOUD_ENABLED", "false");
      expect(isCloud()).toBe(false);
    });

    it("returns false when UI_CLOUD_ENABLED is unset", () => {
      expect(isCloud()).toBe(false);
    });
  });

  describe("with an island (browser)", () => {
    it("uses the island flag over the env var (island true, env false)", () => {
      vi.stubEnv("UI_CLOUD_ENABLED", "false");
      writeIsland({ cloudEnabled: true });
      expect(isCloud()).toBe(true);
    });

    it("uses the island flag over the env var (island false, env true)", () => {
      vi.stubEnv("UI_CLOUD_ENABLED", "true");
      writeIsland({ cloudEnabled: false });
      expect(isCloud()).toBe(false);
    });

    it("falls back to the env var when the island is malformed", () => {
      vi.stubEnv("UI_CLOUD_ENABLED", "true");
      writeIsland("{ not valid json");
      expect(isCloud()).toBe(true);
    });
  });
});
