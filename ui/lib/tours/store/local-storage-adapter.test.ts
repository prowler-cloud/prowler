import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { TOUR_COMPLETION_STATES } from "../tour-types";
import { buildStorageKey, localStorageAdapter } from "./local-storage-adapter";

const TOUR_ID = { id: "attack-paths", version: 1 };
const STORAGE_KEY = "prowler.tour.attack-paths.v1";

const sampleRecord = {
  tourId: "attack-paths",
  version: 1,
  state: TOUR_COMPLETION_STATES.COMPLETED,
  completedAt: "2026-01-15T12:34:56.000Z",
} as const;

describe("buildStorageKey", () => {
  it("composes the documented key format", () => {
    expect(buildStorageKey({ id: "attack-paths", version: 1 })).toBe(
      "prowler.tour.attack-paths.v1",
    );
  });

  it("renders multi-digit versions verbatim", () => {
    expect(buildStorageKey({ id: "lighthouse", version: 42 })).toBe(
      "prowler.tour.lighthouse.v42",
    );
  });
});

describe("localStorageAdapter", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("set/get round-trips a record under the documented key", () => {
    localStorageAdapter.set(TOUR_ID, sampleRecord);

    const raw = window.localStorage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    expect(JSON.parse(raw as string)).toEqual(sampleRecord);

    const fetched = localStorageAdapter.get(TOUR_ID);
    expect(fetched).toEqual(sampleRecord);
  });

  it("returns null when no record exists for that (id, version)", () => {
    expect(localStorageAdapter.get(TOUR_ID)).toBeNull();
  });

  it("isolates records by version under the same id", () => {
    localStorageAdapter.set(TOUR_ID, sampleRecord);

    const v2Record = { ...sampleRecord, version: 2 };
    localStorageAdapter.set({ id: TOUR_ID.id, version: 2 }, v2Record);

    expect(localStorageAdapter.get(TOUR_ID)).toEqual(sampleRecord);
    expect(localStorageAdapter.get({ id: TOUR_ID.id, version: 2 })).toEqual(
      v2Record,
    );
  });

  it("clear() removes only the matching record", () => {
    localStorageAdapter.set(TOUR_ID, sampleRecord);
    localStorageAdapter.set({ id: "other", version: 1 }, sampleRecord);

    localStorageAdapter.clear(TOUR_ID);

    expect(localStorageAdapter.get(TOUR_ID)).toBeNull();
    expect(localStorageAdapter.get({ id: "other", version: 1 })).toEqual(
      sampleRecord,
    );
  });

  it("returns null when stored JSON is malformed", () => {
    window.localStorage.setItem(STORAGE_KEY, "{not json");

    expect(localStorageAdapter.get(TOUR_ID)).toBeNull();
  });

  it("returns null when stored JSON is missing required fields", () => {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ tourId: "attack-paths" }),
    );

    expect(localStorageAdapter.get(TOUR_ID)).toBeNull();
  });
});
