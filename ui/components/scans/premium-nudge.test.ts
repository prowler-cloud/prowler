import { describe, expect, it } from "vitest";

import {
  dismissPremiumNudge,
  isPremiumNudgeDismissed,
  PREMIUM_NUDGE_COOLDOWN_MS,
} from "./premium-nudge";

const memoryStorage = () => {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
  };
};

describe("premium nudge dismissal", () => {
  it("shows a nudge that was never dismissed", () => {
    // Given / When / Then
    expect(isPremiumNudgeDismissed("cli-import", memoryStorage())).toBe(false);
  });

  it("hides a dismissed nudge until the 14-day cooldown ends", () => {
    // Given
    const storage = memoryStorage();
    const dismissedAt = 1_000_000;
    dismissPremiumNudge("cli-import", storage, dismissedAt);

    // When / Then
    expect(
      isPremiumNudgeDismissed(
        "cli-import",
        storage,
        dismissedAt + PREMIUM_NUDGE_COOLDOWN_MS - 1,
      ),
    ).toBe(true);
    expect(
      isPremiumNudgeDismissed(
        "cli-import",
        storage,
        dismissedAt + PREMIUM_NUDGE_COOLDOWN_MS,
      ),
    ).toBe(false);
  });

  it("keeps each nudge's dismissal independent", () => {
    // Given
    const storage = memoryStorage();
    dismissPremiumNudge("cli-import", storage);

    // When / Then
    expect(isPremiumNudgeDismissed("alerts", storage)).toBe(false);
  });
});
