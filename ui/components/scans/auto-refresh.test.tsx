import { render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { navigationState, routerRefreshMock } = vi.hoisted(() => ({
  navigationState: { searchParams: new URLSearchParams() },
  routerRefreshMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: routerRefreshMock }),
  useSearchParams: () => navigationState.searchParams,
}));

import { AutoRefresh, SCAN_DATA_REFRESHED_EVENT } from "./auto-refresh";

describe("AutoRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    navigationState.searchParams = new URLSearchParams();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("dispatches scan data refreshed after a successful callback refresh", async () => {
    // Given
    let resolveRefresh!: () => void;
    const refreshPromise = new Promise<void>((resolve) => {
      resolveRefresh = resolve;
    });
    const onRefresh = vi.fn().mockReturnValue(refreshPromise);
    const eventListener = vi.fn();
    window.addEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
    render(<AutoRefresh hasExecutingScan onRefresh={onRefresh} />);

    // When
    await vi.advanceTimersByTimeAsync(5_000);

    // Then
    expect(onRefresh).toHaveBeenCalledOnce();
    expect(eventListener).not.toHaveBeenCalled();

    // When
    resolveRefresh();
    await refreshPromise;
    await Promise.resolve();

    // Then
    expect(eventListener).toHaveBeenCalledOnce();
    window.removeEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
  });

  it("dispatches scan data refreshed after the default router refresh", async () => {
    // Given
    const eventListener = vi.fn();
    window.addEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
    render(<AutoRefresh hasExecutingScan />);

    // When
    await vi.advanceTimersByTimeAsync(5_000);

    // Then
    expect(routerRefreshMock).toHaveBeenCalledOnce();
    expect(eventListener).toHaveBeenCalledOnce();
    window.removeEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
  });

  it("does not dispatch scan data refreshed when an async callback rejects", async () => {
    // Given
    const onRefresh = vi.fn().mockRejectedValue(new Error("refresh failed"));
    const eventListener = vi.fn();
    window.addEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
    render(<AutoRefresh hasExecutingScan onRefresh={onRefresh} />);

    // When
    await vi.advanceTimersByTimeAsync(5_000);

    // Then
    expect(onRefresh).toHaveBeenCalledOnce();
    expect(eventListener).not.toHaveBeenCalled();
    window.removeEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
  });

  it.each([
    {
      hasExecutingScan: false,
      searchParams: "",
      condition: "no scan executes",
    },
    {
      hasExecutingScan: true,
      searchParams: "scanId=scan-executing",
      condition: "the scan drawer is open",
    },
  ])(
    "does not poll when $condition",
    async ({ hasExecutingScan, searchParams }) => {
      // Given
      const onRefresh = vi.fn();
      const eventListener = vi.fn();
      navigationState.searchParams = new URLSearchParams(searchParams);
      window.addEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
      render(
        <AutoRefresh
          hasExecutingScan={hasExecutingScan}
          onRefresh={onRefresh}
        />,
      );

      // When
      await vi.advanceTimersByTimeAsync(5_000);

      // Then
      expect(onRefresh).not.toHaveBeenCalled();
      expect(eventListener).not.toHaveBeenCalled();
      window.removeEventListener(SCAN_DATA_REFRESHED_EVENT, eventListener);
    },
  );
});
