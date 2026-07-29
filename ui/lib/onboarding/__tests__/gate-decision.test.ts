import { describe, expect, it } from "vitest";

import type { TourCompletionRecord } from "@/lib/tours/tour-types";
import { TOUR_COMPLETION_STATES } from "@/lib/tours/tour-types";

import { shouldStartOnboarding } from "../gate-decision";

const recordWithState = (
  state: TourCompletionRecord["state"],
): TourCompletionRecord => ({
  tourId: "add-provider",
  version: 1,
  state,
  completedAt: "2026-01-15T12:00:00.000Z",
});

describe("shouldStartOnboarding", () => {
  it("returns true for a zero-provider user with no completion record", () => {
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: null,
    });
    expect(result).toBe(true);
  });

  it("returns false when the user already has providers", () => {
    const result = shouldStartOnboarding({
      hasProviders: true,
      completionRecord: null,
    });
    expect(result).toBe(false);
  });

  it("returns false when a dismissed record exists", () => {
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: recordWithState(TOUR_COMPLETION_STATES.DISMISSED),
    });
    expect(result).toBe(false);
  });

  it("returns false when a completed record exists", () => {
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: recordWithState(TOUR_COMPLETION_STATES.COMPLETED),
    });
    expect(result).toBe(false);
  });

  it("returns false when a skipped record exists", () => {
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: recordWithState(TOUR_COMPLETION_STATES.SKIPPED),
    });
    expect(result).toBe(false);
  });

  it("fails open when hasProviders is undefined", () => {
    // strict === false check rejects non-false values; don't force onboarding on unknown state
    const result = shouldStartOnboarding({
      hasProviders: undefined,
      completionRecord: null,
    });
    expect(result).toBe(false);
  });

  it("fails open when hasProviders is null", () => {
    const result = shouldStartOnboarding({
      hasProviders: null as unknown as boolean,
      completionRecord: null,
    });
    expect(result).toBe(false);
  });
});
