import type { TourCompletionRecord, TourId } from "../tour-types";
import type { TourCompletionStore } from "./tour-completion-store";

// All tour completion records live under ONE localStorage key, as a single
// object keyed by `<id>.v<version>`, instead of one key per tour. This keeps the
// browser storage namespace tidy and lets callers never hand-build keys.
const STORAGE_KEY = "prowler.tours";

type ToursObject = Record<string, TourCompletionRecord>;

// Field key for a tour within the single tours object. Composition stays here so
// callers never hand-build keys.
export function buildStorageKey({ id, version }: TourId): string {
  return `${id}.v${version}`;
}

function isValidRecord(value: unknown): value is TourCompletionRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Partial<TourCompletionRecord>;
  return (
    typeof record.tourId === "string" &&
    typeof record.version === "number" &&
    typeof record.state === "string" &&
    typeof record.completedAt === "string"
  );
}

function readAll(): ToursObject {
  if (typeof window === "undefined") return {};

  let raw: string | null;
  try {
    raw = window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return {};
  }
  if (raw === null) return {};

  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null) {
      return parsed as ToursObject;
    }
    return {};
  } catch {
    return {};
  }
}

function writeAll(tours: ToursObject): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(tours));
  } catch {
    // Non-fatal: a re-shown tour beats a thrown render.
  }
}

export const localStorageAdapter: TourCompletionStore = {
  get(id) {
    const record = readAll()[buildStorageKey(id)];
    return isValidRecord(record) ? record : null;
  },
  set(id, record) {
    const tours = readAll();
    tours[buildStorageKey(id)] = record;
    writeAll(tours);
  },
  clear(id) {
    const tours = readAll();
    delete tours[buildStorageKey(id)];
    writeAll(tours);
  },
};
