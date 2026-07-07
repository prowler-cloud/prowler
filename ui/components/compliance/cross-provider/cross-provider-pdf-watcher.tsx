"use client";

import Link from "next/link";
import { useRef } from "react";

import { getTask } from "@/actions/task";
import { toast, ToastAction } from "@/components/ui/toast";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { useCrossProviderPdfStore } from "@/store/cross-provider-pdf/store";
import type { GetTaskResponse, TaskState } from "@/types/tasks";

type PdfTaskResult = { error?: string };

const POLL_INTERVAL_MS = 3000;

// Allowlist of "still running" states rather than hardcoding "done" states:
// treating anything NOT in this set as terminal means an unhandled state
// (e.g. "cancelled", or a future state we don't know about yet) stops
// polling and surfaces an error instead of spinning forever.
const RUNNING_STATES = new Set<TaskState>([
  "available",
  "scheduled",
  "executing",
]);

// Transient getTask failures (network blip, one 5xx) must not abort a
// generation that is still running server-side — give up only after several
// consecutive failures.
const MAX_CONSECUTIVE_POLL_ERRORS = 3;

// Hard ceiling on how long a single generation is polled. A task wedged in
// ``executing`` server-side would otherwise be polled forever; after this many
// ticks (~10 min at a 3s interval) we stop tracking it and tell the user.
const MAX_POLL_TICKS = 200;

/**
 * Inner poller. Mounted by ``CrossProviderPdfWatcher`` ONLY while at least one
 * generation is running, so the app-wide 3s tick exists exclusively during
 * active generations — when everything has settled this component unmounts and
 * the interval is torn down (rather than ticking forever over an empty set).
 */
const PdfGenerationPoller = () => {
  const generations = useCrossProviderPdfStore((state) => state.generations);
  const markCompleted = useCrossProviderPdfStore(
    (state) => state.markCompleted,
  );
  const markFailed = useCrossProviderPdfStore((state) => state.markFailed);

  // Latest generations snapshot for the interval callback to read without
  // being re-created (and re-scheduling the interval) on every store change.
  const generationsRef = useRef(generations);
  generationsRef.current = generations;

  // Per-task bookkeeping (in-flight tick + consecutive error count + elapsed
  // ticks) that must NOT trigger React re-renders — a plain ref keyed by task
  // id.
  const pollStateRef = useRef<
    Map<string, { busy: boolean; errors: number; ticks: number }>
  >(new Map());

  // A single mount-time poller (setup on mount, cleanup on unmount). It reads
  // the live generations snapshot from ``generationsRef`` and the store
  // actions (``markCompleted``/``markFailed``) are stable Zustand references,
  // so capturing them at mount is safe — no dependency array needed.
  useMountEffect(() => {
    const interval = setInterval(() => {
      const running = Object.values(generationsRef.current).filter(
        (generation) => generation.status === "running",
      );

      // Prune bookkeeping for tasks that are no longer running so the map
      // doesn't grow unbounded across a long session.
      const runningIds = new Set(
        running.map((generation) => generation.taskId),
      );
      for (const trackedId of Array.from(pollStateRef.current.keys())) {
        if (!runningIds.has(trackedId)) pollStateRef.current.delete(trackedId);
      }

      for (const generation of running) {
        let pollState = pollStateRef.current.get(generation.taskId);
        if (!pollState) {
          pollState = { busy: false, errors: 0, ticks: 0 };
          pollStateRef.current.set(generation.taskId, pollState);
        }

        // Count elapsed ticks even while a poll is in flight, then give up on a
        // generation that has run past the ceiling — a wedged task must not be
        // polled indefinitely.
        pollState.ticks += 1;
        if (pollState.ticks > MAX_POLL_TICKS) {
          markFailed(generation.taskId);
          toast({
            variant: "destructive",
            title: "PDF generation timed out",
            description:
              "The report is taking longer than expected. Please try generating it again.",
          });
          continue;
        }

        // Skip a task whose previous poll (a whole-task fetch) is still in
        // flight — otherwise a slow tick could double-fire the ready toast.
        if (pollState.busy) continue;
        pollState.busy = true;

        const state = pollState;
        void (async () => {
          try {
            const task = (await getTask(
              generation.taskId,
            )) as GetTaskResponse<PdfTaskResult>;

            if ("error" in task) {
              state.errors += 1;
              if (state.errors < MAX_CONSECUTIVE_POLL_ERRORS) return;
              markFailed(generation.taskId);
              toast({
                variant: "destructive",
                title: "PDF generation failed",
                description: task.error,
              });
              return;
            }
            state.errors = 0;

            const taskState = task.data?.attributes?.state;
            if (taskState && RUNNING_STATES.has(taskState)) return;

            if (taskState === "completed") {
              markCompleted(generation.taskId);
              toast({
                title: "PDF report ready",
                description:
                  "Your combined compliance PDF has been generated and is ready to download.",
                action: generation.reportUrl ? (
                  <ToastAction altText="Go to the report" asChild>
                    <Link href={generation.reportUrl}>View report</Link>
                  </ToastAction>
                ) : undefined,
              });
              return;
            }

            // Any other terminal state ("failed", "cancelled", or an
            // unrecognized one) — stop tracking rather than spin forever.
            markFailed(generation.taskId);
            toast({
              variant: "destructive",
              title: "PDF generation failed",
              description:
                task.data?.attributes?.result?.error ||
                `The report generation task did not complete (state: ${taskState ?? "unknown"}).`,
            });
          } catch (_error) {
            // ``getTask`` is contracted to return a normalized ``{data}``/
            // ``{error}`` shape rather than throw, so this is defense-in-depth:
            // swallow any unexpected throw (from getTask/markCompleted/
            // markFailed/toast) so it never becomes an unhandled rejection.
          } finally {
            state.busy = false;
          }
        })();
      }
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  });

  return null;
};

/**
 * Single, app-wide poller for cross-provider PDF generations.
 *
 * Mounted once in the ``(prowler)`` layout so it survives navigation between
 * views. When the user clicks "Generate PDF" the button registers the task in
 * ``useCrossProviderPdfStore`` and unmounts freely; this watcher keeps polling
 * every tracked generation and fires the "ready"/"failed" toast when each one
 * settles — so the notification arrives even if the user has since switched to
 * the overview or another framework. The toast's action links back to the
 * exact page the report was generated from (where the button now offers
 * "Download PDF").
 *
 * The actual interval lives in ``PdfGenerationPoller``, mounted here only while
 * a generation is running: instead of a bare ``useEffect`` guard inside the
 * poller, conditional mounting means the app carries no ticking timer at all
 * once every generation has settled.
 */
export const CrossProviderPdfWatcher = () => {
  const hasRunningGeneration = useCrossProviderPdfStore((state) =>
    Object.values(state.generations).some(
      (generation) => generation.status === "running",
    ),
  );

  if (!hasRunningGeneration) return null;
  return <PdfGenerationPoller />;
};
