import { afterEach, describe, expect, it } from "vitest";

import {
  clearAllOptimisticEntries,
  loadOptimisticallyMutedCheckIds,
  OPTIMISTIC_MUTED_GROUPS_TTL_MS,
  persistOptimisticallyMutedCheckIds,
  removePersistedOptimisticEntries,
} from "./optimistic-muted-groups";

const STORAGE_KEY = "prowler:optimistic-muted-groups";

describe("optimistic-muted-groups", () => {
  afterEach(() => {
    sessionStorage.clear();
  });

  it("returns an empty set when storage is empty", () => {
    expect(loadOptimisticallyMutedCheckIds()).toEqual(new Set());
  });

  it("persists ids and reloads them within the TTL window", () => {
    persistOptimisticallyMutedCheckIds(["check-a", "check-b"], 1_000);

    expect(loadOptimisticallyMutedCheckIds(1_500)).toEqual(
      new Set(["check-a", "check-b"]),
    );
  });

  it("prunes expired entries on load and rewrites storage", () => {
    persistOptimisticallyMutedCheckIds(["check-old"], 0);
    persistOptimisticallyMutedCheckIds(
      ["check-fresh"],
      OPTIMISTIC_MUTED_GROUPS_TTL_MS - 1_000,
    );

    const result = loadOptimisticallyMutedCheckIds(
      OPTIMISTIC_MUTED_GROUPS_TTL_MS + 100,
    );

    expect(result).toEqual(new Set(["check-fresh"]));
    const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(Object.keys(stored)).toEqual(["check-fresh"]);
  });

  it("removes only the listed ids and keeps the rest", () => {
    persistOptimisticallyMutedCheckIds(["check-a", "check-b", "check-c"], 0);

    removePersistedOptimisticEntries(["check-b"]);

    expect(loadOptimisticallyMutedCheckIds(1_000)).toEqual(
      new Set(["check-a", "check-c"]),
    );
  });

  it("refreshes expiresAt when persisting an existing id", () => {
    persistOptimisticallyMutedCheckIds(["check-a"], 0);
    const firstStored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) ?? "{}");

    persistOptimisticallyMutedCheckIds(["check-a"], 5_000);
    const secondStored = JSON.parse(
      sessionStorage.getItem(STORAGE_KEY) ?? "{}",
    );

    expect(secondStored["check-a"].expiresAt).toBeGreaterThan(
      firstStored["check-a"].expiresAt,
    );
  });

  it("removes the storage entry when the map becomes empty", () => {
    persistOptimisticallyMutedCheckIds(["check-a"], 0);
    expect(sessionStorage.getItem(STORAGE_KEY)).not.toBeNull();

    removePersistedOptimisticEntries(["check-a"]);

    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("ignores corrupted storage payloads", () => {
    sessionStorage.setItem(STORAGE_KEY, "not-json");
    expect(loadOptimisticallyMutedCheckIds()).toEqual(new Set());
  });

  it("clearAllOptimisticEntries removes the storage entry", () => {
    persistOptimisticallyMutedCheckIds(["check-a"], 0);
    clearAllOptimisticEntries();
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});
