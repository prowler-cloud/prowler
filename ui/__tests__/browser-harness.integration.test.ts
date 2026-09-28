/**
 * Covers only the polling contract of `BrowserHarness`, which every page
 * harness inherits: a silent `null` where a predicate actually threw sends the
 * caller hunting a phantom timeout. Lives in the browser project because the
 * base class imports `vitest/browser`.
 */
import { describe, expect, it } from "vitest";

import { BrowserHarness } from "./browser-harness";

/** Exposes the protected waiting helpers; no fixture or DOM is involved. */
class WaitingHarness extends BrowserHarness<null> {
  constructor() {
    super(null);
  }

  probe<T>(fn: () => T | null | undefined | false): Promise<T> {
    return this.waitFor(fn, 200, "probe", 10);
  }

  probeOrNull<T>(fn: () => T | null | undefined | false): Promise<T | null> {
    return this.waitForOrNull(fn, 200, "probe");
  }
}

describe("BrowserHarness waiting helpers", () => {
  it("resolves to null when the predicate only ever stays falsy", async () => {
    const harness = new WaitingHarness();

    await expect(harness.probeOrNull<string>(() => null)).resolves.toBeNull();
  });

  it("rejects with the predicate's error when it throws and then goes falsy", async () => {
    const harness = new WaitingHarness();
    const boom = new Error("predicate blew up");
    let calls = 0;

    // `vi.waitFor` polls past a throw and rejects with the *last* error, so the
    // falsy polls would otherwise bury `boom` under the timeout sentinel.
    await expect(
      harness.probeOrNull<string>(() => {
        calls += 1;
        if (calls === 1) throw boom;
        return null;
      }),
    ).rejects.toBe(boom);
  });

  it("still polls through a transient throw", async () => {
    const harness = new WaitingHarness();
    let calls = 0;

    await expect(
      harness.probe(() => {
        calls += 1;
        if (calls === 1) throw new Error("transient");
        return "ready";
      }),
    ).resolves.toBe("ready");
  });
});
