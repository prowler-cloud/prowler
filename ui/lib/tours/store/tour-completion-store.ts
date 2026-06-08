import type { TourCompletionRecord, TourId } from "../tour-types";

// Persistence backend contract; swap the adapter without touching consumers.
export interface TourCompletionStore {
  get(id: TourId): TourCompletionRecord | null;
  set(id: TourId, record: TourCompletionRecord): void;
  clear(id: TourId): void;
}
