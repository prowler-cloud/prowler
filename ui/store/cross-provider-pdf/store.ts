import { create } from "zustand";

export const PDF_GENERATION_STATUS = {
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;
export type PdfGenerationStatus =
  (typeof PDF_GENERATION_STATUS)[keyof typeof PDF_GENERATION_STATUS];

/** A single in-flight (or just-finished) cross-provider PDF generation. */
export interface CrossProviderPdfGeneration {
  /** The generation task id returned by the server action. */
  taskId: string;
  /**
   * The filter signature the generation was started under (framework +
   * scan ids + provider filters). A ``GeneratePdfButton`` only offers a
   * finished report for download when its own current signature matches
   * this — a report generated under the previous filters must never be
   * served under new ones.
   */
  signature: string;
  /**
   * Absolute path + search of the page the generation was started from, so
   * the "ready" toast can send the user back to exactly where they
   * generated it — even if they navigated away while it was rendering.
   */
  reportUrl: string;
  status: PdfGenerationStatus;
}

interface CrossProviderPdfState {
  /** Tracked generations keyed by task id. */
  generations: Record<string, CrossProviderPdfGeneration>;
  /** Register a newly started generation as ``running``. */
  trackGeneration: (entry: Omit<CrossProviderPdfGeneration, "status">) => void;
  markCompleted: (taskId: string) => void;
  markFailed: (taskId: string) => void;
  /** Forget a generation entirely (e.g. its file expired on download). */
  removeGeneration: (taskId: string) => void;
}

const setStatus = (
  generations: Record<string, CrossProviderPdfGeneration>,
  taskId: string,
  status: CrossProviderPdfGeneration["status"],
): Record<string, CrossProviderPdfGeneration> => {
  const entry = generations[taskId];
  if (!entry || entry.status === status) return generations;
  return { ...generations, [taskId]: { ...entry, status } };
};

/**
 * Global registry of in-flight cross-provider PDF generations.
 *
 * The generation job has no fixed time budget, so completion is detected by
 * client-side polling. That polling lives in a single ``CrossProviderPdfWatcher``
 * mounted once in the app layout (NOT in the ``GeneratePdfButton``) so the
 * "ready" notification still fires after the user navigates away from the
 * page they generated the report on — the button unmounts, but the watcher
 * and this store persist across route changes.
 *
 * In-memory only (like the other UI stores): a full browser reload mid-
 * generation drops tracking, which is acceptable — the reported gap is SPA
 * navigation within the app, where the store stays alive.
 */
export const useCrossProviderPdfStore = create<CrossProviderPdfState>(
  (set) => ({
    generations: {},
    trackGeneration: (entry) =>
      set((state) => ({
        generations: {
          ...state.generations,
          [entry.taskId]: {
            ...entry,
            status: PDF_GENERATION_STATUS.RUNNING,
          },
        },
      })),
    markCompleted: (taskId) =>
      set((state) => ({
        generations: setStatus(
          state.generations,
          taskId,
          PDF_GENERATION_STATUS.COMPLETED,
        ),
      })),
    markFailed: (taskId) =>
      set((state) => ({
        generations: setStatus(
          state.generations,
          taskId,
          PDF_GENERATION_STATUS.FAILED,
        ),
      })),
    removeGeneration: (taskId) =>
      set((state) => {
        if (!state.generations[taskId]) return state;
        const next = { ...state.generations };
        delete next[taskId];
        return { generations: next };
      }),
  }),
);
