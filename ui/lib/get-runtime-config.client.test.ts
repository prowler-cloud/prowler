import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RUNTIME_CONFIG_SCRIPT_ID } from "./runtime-config.shared";

const writeIsland = (content: string) => {
  const el = document.createElement("script");
  el.id = RUNTIME_CONFIG_SCRIPT_ID;
  el.type = "application/json";
  // textContent (not innerHTML) mirrors how the browser parses an
  // application/json island: the escaped < sequences are already decoded.
  el.textContent = content;
  document.head.appendChild(el);
};

describe("getRuntimeConfigClient", () => {
  beforeEach(() => {
    // Reset modules so each dynamic import re-evaluates the file and its
    // module-level memoization cache starts empty.
    vi.resetModules();
    document.head.innerHTML = "";
  });

  afterEach(() => {
    document.head.innerHTML = "";
  });

  it("parses the data island when present", async () => {
    // Given
    writeIsland(
      JSON.stringify({
        sentryDsn: "https://key@o0.ingest.sentry.io/1",
        apiBaseUrl: "https://api.example.com/api/v1",
      }),
    );
    const { getRuntimeConfigClient } = await import(
      "./get-runtime-config.client"
    );

    // When
    const config = getRuntimeConfigClient();

    // Then
    expect(config.sentryDsn).toBe("https://key@o0.ingest.sentry.io/1");
    expect(config.apiBaseUrl).toBe("https://api.example.com/api/v1");
    // Keys not present in the island fall back to null.
    expect(config.googleTagManagerId).toBeNull();
    expect(config.posthogKey).toBeNull();
  });

  it("falls back to an all-null config when the island is absent", async () => {
    // Given no island in the document
    const { getRuntimeConfigClient } = await import(
      "./get-runtime-config.client"
    );

    // When
    const config = getRuntimeConfigClient();

    // Then
    expect(config.sentryDsn).toBeNull();
    expect(config.apiBaseUrl).toBeNull();
    expect(config.reoDevClientId).toBeNull();
  });

  it("falls back to an all-null config when the island is malformed JSON", async () => {
    // Given
    writeIsland("{ not valid json");
    const { getRuntimeConfigClient } = await import(
      "./get-runtime-config.client"
    );

    // When
    const config = getRuntimeConfigClient();

    // Then
    expect(config.sentryDsn).toBeNull();
    expect(config.apiBaseUrl).toBeNull();
  });

  it("exposes only the allowlisted keys and ignores anything extra", async () => {
    // Given an island carrying an unexpected key and a __proto__ payload
    writeIsland(
      JSON.stringify({
        apiBaseUrl: "https://api.example.com/api/v1",
        notAllowlisted: "should-not-survive",
        __proto__: { polluted: true },
      }),
    );
    const { getRuntimeConfigClient } = await import(
      "./get-runtime-config.client"
    );

    // When
    const config = getRuntimeConfigClient();

    // Then - exactly the eight allowlisted keys, nothing else
    expect(Object.keys(config).sort()).toEqual(
      [
        "apiBaseUrl",
        "apiDocsUrl",
        "googleTagManagerId",
        "posthogHost",
        "posthogKey",
        "reoDevClientId",
        "sentryDsn",
        "sentryEnvironment",
      ].sort(),
    );
    expect(config.apiBaseUrl).toBe("https://api.example.com/api/v1");
    expect(
      (config as unknown as Record<string, unknown>).notAllowlisted,
    ).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});
