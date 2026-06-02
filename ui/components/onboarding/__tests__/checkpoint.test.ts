import { describe, expect, it } from "vitest";

import { isCheckpointArmed, shouldFireCheckpoint } from "../checkpoint.logic";

describe("isCheckpointArmed", () => {
  it("arms on a concrete false -> true flip that has not been handled", () => {
    // Given - the user just connected their first provider, unhandled
    // When/Then - the checkpoint is armed regardless of wizard state
    expect(isCheckpointArmed({ prev: false, next: true, handled: false })).toBe(
      true,
    );
  });

  it("does not arm on an undefined -> true initial read", () => {
    // Given - the user already had providers (no transition observed)
    // When/Then - never arm on the first read
    expect(
      isCheckpointArmed({ prev: undefined, next: true, handled: false }),
    ).toBe(false);
  });

  it("does not arm on a true -> true steady state", () => {
    expect(isCheckpointArmed({ prev: true, next: true, handled: false })).toBe(
      false,
    );
  });

  it("does not arm on a flip that was already handled", () => {
    expect(isCheckpointArmed({ prev: false, next: true, handled: true })).toBe(
      false,
    );
  });

  it("does not arm on a false -> false steady state", () => {
    expect(
      isCheckpointArmed({ prev: false, next: false, handled: false }),
    ).toBe(false);
  });

  it("does not arm on a true -> false regression", () => {
    expect(isCheckpointArmed({ prev: true, next: false, handled: false })).toBe(
      false,
    );
  });
});

describe("shouldFireCheckpoint", () => {
  it("fires on a concrete false -> true flip that has not been handled while no wizard is open", () => {
    // Given - the user just connected their first provider, unhandled, the
    // wizard already closed
    // When/Then - the checkpoint fires
    expect(
      shouldFireCheckpoint({
        prev: false,
        next: true,
        handled: false,
        wizardOpen: false,
      }),
    ).toBe(true);
  });

  it("does NOT fire while the provider wizard is still open even on a real flip", () => {
    // Given - the provider record was created on the wizard's first step, so
    // hasProviders flips true MID-WIZARD
    // When/Then - the checkpoint must wait; opening it would close the wizard
    expect(
      shouldFireCheckpoint({
        prev: false,
        next: true,
        handled: false,
        wizardOpen: true,
      }),
    ).toBe(false);
  });

  it("does not fire on an undefined -> true initial read", () => {
    // Given - the user already had providers (no transition observed)
    // When/Then - the checkpoint must NOT fire on the first read
    expect(
      shouldFireCheckpoint({
        prev: undefined,
        next: true,
        handled: false,
        wizardOpen: false,
      }),
    ).toBe(false);
  });

  it("does not fire on a true -> true steady state", () => {
    // Given - providers were already present and stay present
    // When/Then - no flip, no checkpoint
    expect(
      shouldFireCheckpoint({
        prev: true,
        next: true,
        handled: false,
        wizardOpen: false,
      }),
    ).toBe(false);
  });

  it("does not fire on a false -> true flip that was already handled", () => {
    // Given - the flip happened but the user already chose continue/finish
    // When/Then - the marker suppresses re-appearance
    expect(
      shouldFireCheckpoint({
        prev: false,
        next: true,
        handled: true,
        wizardOpen: false,
      }),
    ).toBe(false);
  });

  it("does not fire on a false -> false steady state", () => {
    // Given - still no providers
    // When/Then - nothing to celebrate yet
    expect(
      shouldFireCheckpoint({
        prev: false,
        next: false,
        handled: false,
        wizardOpen: false,
      }),
    ).toBe(false);
  });

  it("does not fire on a true -> false regression", () => {
    // Given - providers disappeared (e.g. deleted)
    // When/Then - the checkpoint is only about gaining the first provider
    expect(
      shouldFireCheckpoint({
        prev: true,
        next: false,
        handled: false,
        wizardOpen: false,
      }),
    ).toBe(false);
  });
});
