import { describe, expect, it } from "vitest";

import { shouldStartOnboardingProfile } from "../profile-gate-decision";

describe("shouldStartOnboardingProfile", () => {
  it("opens for a zero-provider tenant with no profile and no local marker", () => {
    expect(
      shouldStartOnboardingProfile({
        hasProviders: false,
        profileRecorded: false,
        handledLocally: false,
      }),
    ).toBe(true);
  });

  it.each([
    ["providers already exist", { hasProviders: true }],
    ["the providers read failed", { hasProviders: undefined }],
    ["a profile is already recorded", { profileRecorded: true }],
    ["the profile read failed", { profileRecorded: undefined }],
    ["this browser already resolved the step", { handledLocally: true }],
  ])("stays closed when %s", (_, override) => {
    expect(
      shouldStartOnboardingProfile({
        hasProviders: false,
        profileRecorded: false,
        handledLocally: false,
        ...override,
      }),
    ).toBe(false);
  });
});
