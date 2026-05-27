import type { TourCompletionRecord, TourId } from "../tour-types";

/**
 * Swappable persistence interface for tour completion state.
 *
 * The PoC ships a single `localStorage` adapter; an API-backed adapter is
 * documented for v1 but not built. All adapters MUST agree on this
 * contract so consumers (the `useDriverTour` hook) never branch on
 * implementation.
 */
export interface TourCompletionStore {
  get(id: TourId): TourCompletionRecord | null;
  set(id: TourId, record: TourCompletionRecord): void;
  clear(id: TourId): void;
}
