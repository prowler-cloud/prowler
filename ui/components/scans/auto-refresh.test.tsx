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

import {
  AutoRefresh,
  SCAN_EXECUTION_SETTLED_EVENT,
  SCAN_POLL_TICK_EVENT,
} from "./auto-refresh";

describe("AutoRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    navigationState.searchParams = new URLSearchParams();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("dispatches a poll tick after a successful callback refresh", async () => {
    // Given
    let resolveRefresh!: () => void;
    const refreshPromise = new Promise<void>((resolve) => {
      resolveRefresh = resolve;
    });
    const onRefresh = vi.fn().mockReturnValue(refreshPromise);
    const eventListener = vi.fn();
    window.addEventListener(SCAN_POLL_TICK_EVENT, eventListener);
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
    window.removeEventListener(SCAN_POLL_TICK_EVENT, eventListener);
  });

  it("dispatches a poll tick after the default router refresh", async () => {
    // Given
    const eventListener = vi.fn();
    window.addEventListener(SCAN_POLL_TICK_EVENT, eventListener);
    render(<AutoRefresh hasExecutingScan />);

    // When
    await vi.advanceTimersByTimeAsync(5_000);

    // Then
    expect(routerRefreshMock).toHaveBeenCalledOnce();
    expect(eventListener).toHaveBeenCalledOnce();
    window.removeEventListener(SCAN_POLL_TICK_EVENT, eventListener);
  });

  it("does not dispatch a poll tick when an async callback rejects", async () => {
    // Given
    const onRefresh = vi.fn().mockRejectedValue(new Error("refresh failed"));
    const eventListener = vi.fn();
    window.addEventListener(SCAN_POLL_TICK_EVENT, eventListener);
    render(<AutoRefresh hasExecutingScan onRefresh={onRefresh} />);

    // When
    await vi.advanceTimersByTimeAsync(5_000);

    // Then
    expect(onRefresh).toHaveBeenCalledOnce();
    expect(eventListener).not.toHaveBeenCalled();
    window.removeEventListener(SCAN_POLL_TICK_EVENT, eventListener);
  });

  it("does not start another refresh while the previous one is pending", async () => {
    // Given
    let resolveRefresh!: () => void;
    const refreshPromise = new Promise<void>((resolve) => {
      resolveRefresh = resolve;
    });
    const onRefresh = vi.fn().mockReturnValue(refreshPromise);
    render(<AutoRefresh hasExecutingScan onRefresh={onRefresh} />);

    // When
    await vi.advanceTimersByTimeAsync(10_000);

    // Then
    expect(onRefresh).toHaveBeenCalledOnce();

    // When
    resolveRefresh();
    await refreshPromise;
    await vi.advanceTimersByTimeAsync(5_000);

    // Then
    expect(onRefresh).toHaveBeenCalledTimes(2);
  });

  it("does not dispatch a poll tick after unmounting a pending refresh", async () => {
    // Given
    let resolveRefresh!: () => void;
    const refreshPromise = new Promise<void>((resolve) => {
      resolveRefresh = resolve;
    });
    const onRefresh = vi.fn().mockReturnValue(refreshPromise);
    const eventListener = vi.fn();
    window.addEventListener(SCAN_POLL_TICK_EVENT, eventListener);
    const { unmount } = render(
      <AutoRefresh hasExecutingScan onRefresh={onRefresh} />,
    );
    await vi.advanceTimersByTimeAsync(5_000);

    // When
    unmount();
    resolveRefresh();
    await refreshPromise;
    await Promise.resolve();

    // Then
    expect(onRefresh).toHaveBeenCalledOnce();
    expect(eventListener).not.toHaveBeenCalled();
    window.removeEventListener(SCAN_POLL_TICK_EVENT, eventListener);
  });

  it("signals when scan execution settles", () => {
    // Given
    const eventListener = vi.fn();
    window.addEventListener(SCAN_EXECUTION_SETTLED_EVENT, eventListener);
    const { rerender } = render(<AutoRefresh hasExecutingScan />);

    // When
    rerender(<AutoRefresh hasExecutingScan={false} />);
    rerender(<AutoRefresh hasExecutingScan={false} />);

    // Then
    expect(eventListener).toHaveBeenCalledOnce();
    window.removeEventListener(SCAN_EXECUTION_SETTLED_EVENT, eventListener);
  });

  it("does not signal settled execution on an idle initial render", () => {
    // Given
    const eventListener = vi.fn();
    window.addEventListener(SCAN_EXECUTION_SETTLED_EVENT, eventListener);

    // When
    render(<AutoRefresh hasExecutingScan={false} />);

    // Then
    expect(eventListener).not.toHaveBeenCalled();
    window.removeEventListener(SCAN_EXECUTION_SETTLED_EVENT, eventListener);
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
      window.addEventListener(SCAN_POLL_TICK_EVENT, eventListener);
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
      window.removeEventListener(SCAN_POLL_TICK_EVENT, eventListener);
    },
  );
});
