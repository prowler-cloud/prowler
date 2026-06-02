import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { addProviderTour } from "../add-provider.tour";
import type { TourCompletionRecord } from "../tour-types";
import { useDriverTour } from "../use-driver-tour";

// The hook short-circuits its driver.js effect when `NODE_ENV === "test"`, so
// these tests assert the PUBLIC contract: the additive `onClosed` option is
// accepted and does NOT change the returned result shape. Driver.js close
// behavior is covered by E2E (slice 9).

function HookProbe({
  onClosed,
  onResult,
}: {
  onClosed?: (state: TourCompletionRecord["state"]) => void;
  onResult: (result: ReturnType<typeof useDriverTour>) => void;
}) {
  const result = useDriverTour(addProviderTour, { autoOpen: false, onClosed });
  onResult(result);
  return null;
}

describe("useDriverTour onClosed option", () => {
  it("accepts the onClosed option and returns the existing result surface", () => {
    // Given - a consumer that passes the additive onClosed callback
    const onClosed = vi.fn();
    const results: ReturnType<typeof useDriverTour>[] = [];

    // When - the hook renders with onClosed
    render(<HookProbe onClosed={onClosed} onResult={(r) => results.push(r)} />);

    // Then - the public result is unchanged (start, stop, hasCompleted)
    const result = results.at(-1);
    expect(result).toBeDefined();
    expect(typeof result?.start).toBe("function");
    expect(typeof result?.stop).toBe("function");
    expect(typeof result?.hasCompleted).toBe("boolean");
    // And the result surface exposes no onClosed (it is input-only)
    expect(result && "onClosed" in result).toBe(false);
  });

  it("keeps the same result surface when onClosed is omitted (backward-compatible)", () => {
    // Given - an existing caller that omits onClosed
    const results: ReturnType<typeof useDriverTour>[] = [];

    // When - the hook renders without onClosed
    render(<HookProbe onResult={(r) => results.push(r)} />);

    // Then - the result is identical in shape
    const result = results.at(-1);
    expect(result).toBeDefined();
    expect(typeof result?.start).toBe("function");
    expect(typeof result?.stop).toBe("function");
    expect(typeof result?.hasCompleted).toBe("boolean");
  });
});
