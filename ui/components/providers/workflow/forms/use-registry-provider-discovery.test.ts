import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getInstalledRegistryProviderOptions } from "@/actions/registry/registry";
import type { RegistryProviderDiscoveryResult } from "@/lib/registry/provider-options";

import { useRegistryProviderDiscovery } from "./use-registry-provider-discovery";

vi.mock("@/actions/registry/registry", () => ({
  getInstalledRegistryProviderOptions: vi.fn(),
}));

function deferred() {
  let resolve!: (value: RegistryProviderDiscoveryResult) => void;
  const promise = new Promise<RegistryProviderDiscoveryResult>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("useRegistryProviderDiscovery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
  });

  it("ignores a stale discovery that settles after a newer one", async () => {
    // Given
    const initial = deferred();
    const afterChange = deferred();
    vi.mocked(getInstalledRegistryProviderOptions)
      .mockReturnValueOnce(initial.promise)
      .mockReturnValueOnce(afterChange.promise);
    const { result } = renderHook(() => useRegistryProviderDiscovery());

    // When
    act(() => {
      window.dispatchEvent(new Event("registry-artifacts-changed"));
    });
    await act(async () => {
      afterChange.resolve({ status: "subscription_required" });
    });
    await act(async () => {
      initial.resolve({ status: "ready", options: [] });
    });

    // Then
    await waitFor(() =>
      expect(result.current.result).toEqual({
        status: "subscription_required",
      }),
    );
  });

  it("applies a retry even when the request it replaces settles later", async () => {
    // Given
    const initial = deferred();
    const retry = deferred();
    vi.mocked(getInstalledRegistryProviderOptions)
      .mockReturnValueOnce(initial.promise)
      .mockReturnValueOnce(retry.promise);
    const { result } = renderHook(() => useRegistryProviderDiscovery());

    // When
    act(() => result.current.retryDiscovery());
    await act(async () => {
      retry.resolve({ status: "onboarding" });
    });
    await act(async () => {
      initial.resolve({ status: "error" });
    });

    // Then
    await waitFor(() => expect(result.current.isRetryingDiscovery).toBe(false));
    expect(result.current.result).toEqual({ status: "onboarding" });
  });
});
