import { beforeEach, describe, expect, it } from "vitest";

import { usePageReadyStore } from "../page-ready";

const reset = () => usePageReadyStore.setState({ readyPath: null });

describe("usePageReadyStore", () => {
  beforeEach(reset);

  it("marks a route ready", () => {
    usePageReadyStore.getState().markReady("/compliance");
    expect(usePageReadyStore.getState().readyPath).toBe("/compliance");
  });

  it("clears readiness only when the path still matches", () => {
    const store = usePageReadyStore.getState();
    store.markReady("/compliance");
    store.clearReady("/compliance");
    expect(usePageReadyStore.getState().readyPath).toBeNull();
  });

  it("ignores a stale clear once a newer route is ready", () => {
    const store = usePageReadyStore.getState();
    // Fast navigation: /findings mounts and marks itself ready before the old
    // /compliance marker's cleanup runs. The stale clear must not wipe it.
    store.markReady("/compliance");
    store.markReady("/findings");
    store.clearReady("/compliance");
    expect(usePageReadyStore.getState().readyPath).toBe("/findings");
  });
});
