import type { TourCompletionRecord, TourId } from "../tour-types";

// Swap point for persistence backends. Consumers must never branch on the
// implementation; all adapters honor this contract.
export interface TourCompletionStore {
  get(id: TourId): TourCompletionRecord | null;
  set(id: TourId, record: TourCompletionRecord): void;
  clear(id: TourId): void;
}
