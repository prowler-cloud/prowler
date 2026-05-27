import type { TourCompletionRecord, TourId } from "../tour-types";
import type { TourCompletionStore } from "./tour-completion-store";

const KEY_PREFIX = "prowler.tour";

/**
 * Key composition lives in the adapter (not in `TourId`) so that callers
 * pass the structured identity around and never hand-build storage keys.
 */
export function buildStorageKey({ id, version }: TourId): string {
  return `${KEY_PREFIX}.${id}.v${version}`;
}

function readSafely(key: string): TourCompletionRecord | null {
  if (typeof window === "undefined") {
    return null;
  }

  let raw: string | null;
  try {
    raw = window.localStorage.getItem(key);
  } catch {
    return null;
  }
  if (raw === null) return null;

  try {
    const parsed = JSON.parse(raw) as TourCompletionRecord;
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof parsed.tourId === "string" &&
      typeof parsed.version === "number" &&
      typeof parsed.state === "string" &&
      typeof parsed.completedAt === "string"
    ) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

function writeSafely(key: string, record: TourCompletionRecord): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, JSON.stringify(record));
  } catch {
    // Quota or privacy-mode failures are non-fatal: a re-shown tour is
    // strictly better than a thrown render.
  }
}

function clearSafely(key: string): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Same rationale as writeSafely.
  }
}

export const localStorageAdapter: TourCompletionStore = {
  get(id) {
    return readSafely(buildStorageKey(id));
  },
  set(id, record) {
    writeSafely(buildStorageKey(id), record);
  },
  clear(id) {
    clearSafely(buildStorageKey(id));
  },
};
