import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RUNTIME_CONFIG_SCRIPT_ID } from "@/lib/runtime-config.shared";

const writeIsland = (content: string) => {
  const el = document.createElement("script");
  el.id = RUNTIME_CONFIG_SCRIPT_ID;
  el.type = "application/json";
  el.textContent = content;
  document.head.appendChild(el);
};

describe("useRuntimeConfig", () => {
  beforeEach(() => {
    // Reset modules so the underlying reader's memoization cache starts empty.
    vi.resetModules();
    document.head.innerHTML = "";
  });

  afterEach(() => {
    document.head.innerHTML = "";
  });

  it("should expose the runtime config island to client components", async () => {
    // Given
    writeIsland(
      JSON.stringify({ apiDocsUrl: "https://self-hosted.example/api/v1/docs" }),
    );
    const { useRuntimeConfig } = await import("./use-runtime-config");

    // When
    const { result } = renderHook(() => useRuntimeConfig());

    // Then
    expect(result.current.apiDocsUrl).toBe(
      "https://self-hosted.example/api/v1/docs",
    );
  });

  it("should return an all-null config when the island is absent", async () => {
    // Given no island in the document
    const { useRuntimeConfig } = await import("./use-runtime-config");

    // When
    const { result } = renderHook(() => useRuntimeConfig());

    // Then
    expect(result.current.apiDocsUrl).toBeNull();
    expect(result.current.apiBaseUrl).toBeNull();
  });
});
