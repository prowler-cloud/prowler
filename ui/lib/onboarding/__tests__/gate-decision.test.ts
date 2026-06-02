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
    // Given - no providers, nothing recorded yet
    // When
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: null,
    });

    // Then - the mandatory gate fires
    expect(result).toBe(true);
  });

  it("returns false when the user already has providers", () => {
    // Given - providers exist, no record
    // When
    const result = shouldStartOnboarding({
      hasProviders: true,
      completionRecord: null,
    });

    // Then
    expect(result).toBe(false);
  });

  it("returns false when a dismissed record exists", () => {
    // Given - user previously dismissed the modal
    // When
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: recordWithState(TOUR_COMPLETION_STATES.DISMISSED),
    });

    // Then
    expect(result).toBe(false);
  });

  it("returns false when a completed record exists", () => {
    // Given - user already completed the tour in this browser
    // When
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: recordWithState(TOUR_COMPLETION_STATES.COMPLETED),
    });

    // Then
    expect(result).toBe(false);
  });

  it("returns false when a skipped record exists", () => {
    // Given - user skipped the tour mid-flow
    // When
    const result = shouldStartOnboarding({
      hasProviders: false,
      completionRecord: recordWithState(TOUR_COMPLETION_STATES.SKIPPED),
    });

    // Then
    expect(result).toBe(false);
  });

  it("fails open when hasProviders is undefined", () => {
    // Given - ambiguous provider signal (undefined)
    // When - strict === false check rejects non-false values
    const result = shouldStartOnboarding({
      hasProviders: undefined as unknown as boolean,
      completionRecord: null,
    });

    // Then - do not force onboarding on an unknown state
    expect(result).toBe(false);
  });

  it("fails open when hasProviders is null", () => {
    // Given - ambiguous provider signal (null)
    // When
    const result = shouldStartOnboarding({
      hasProviders: null as unknown as boolean,
      completionRecord: null,
    });

    // Then
    expect(result).toBe(false);
  });
});
