import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RealtimeResult } from "@/types/realtime";

import { useRealtimeResource } from "./use-realtime-resource";

const ok = (data: string): RealtimeResult<string> => ({ ok: true, data });

const deferred = () => {
  let resolve!: (value: RealtimeResult<string>) => void;
  const promise = new Promise<RealtimeResult<string>>((r) => (resolve = r));
  return { promise, resolve };
};

describe("useRealtimeResource", () => {
  afterEach(() => vi.useRealTimers());

  it("hides the previous key's data until the new key loads", async () => {
    const next = deferred();
    const fetcher = vi
      .fn<() => Promise<RealtimeResult<string>>>()
      .mockResolvedValueOnce(ok("p1"))
      .mockReturnValueOnce(next.promise);
    const { result, rerender } = renderHook(
      ({ key }) => useRealtimeResource(fetcher, key),
      { initialProps: { key: "p1" } },
    );
    await waitFor(() => expect(result.current.data).toBe("p1"));

    rerender({ key: "p2" });
    expect(result.current.data).toBeUndefined();
    expect(result.current.loading).toBe(true);

    await act(async () => next.resolve(ok("p2")));
    expect(result.current.data).toBe("p2");
  });

  it("turns a rejected fetch into a failure", async () => {
    const fetcher = vi.fn().mockRejectedValue(new Error("transport"));
    const { result } = renderHook(() => useRealtimeResource(fetcher, "k"));

    await waitFor(() => expect(result.current.failure?.status).toBe(0));
    expect(result.current.loading).toBe(false);
  });

  it("drops a poll answer that a newer poll overtook", async () => {
    vi.useFakeTimers();
    const slow = deferred();
    const fetcher = vi
      .fn<() => Promise<RealtimeResult<string>>>()
      .mockResolvedValueOnce(ok("first"))
      .mockReturnValueOnce(slow.promise)
      .mockResolvedValueOnce(ok("newest"));
    const { result } = renderHook(() =>
      useRealtimeResource(fetcher, "k", { intervalMs: 1000 }),
    );
    await act(async () => {});
    expect(result.current.data).toBe("first");

    await act(async () => vi.advanceTimersByTime(1000)); // starts the slow poll
    await act(async () => vi.advanceTimersByTime(1000)); // newer poll wins
    expect(result.current.data).toBe("newest");

    await act(async () => slow.resolve(ok("stale")));
    expect(result.current.data).toBe("newest");
  });
});
