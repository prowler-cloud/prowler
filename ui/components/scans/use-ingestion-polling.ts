"use client";

import { useEffect, useRef } from "react";

import { INGESTION_STATUS, type Ingestion } from "@/types";

const POLL_INTERVAL_MS = 5000;
// 60 polls at 5s = ~5 min of watching; timing out ends the watch, not the job.
const MAX_POLL_ATTEMPTS = 60;
const STATUS_ERROR = "Unable to check the import status. Please try again.";
const STATUS_TIMEOUT =
  "Import is taking longer than expected — it may still be running in the background.";

export interface IngestionPollingTarget {
  file: File;
  ingestion: Ingestion;
}

interface UseIngestionPollingOptions {
  onCompleted: (ingestion: Ingestion, completedWhileHidden: boolean) => void;
  onFailed: (target: IngestionPollingTarget) => void;
  onProgress: (target: IngestionPollingTarget) => void;
  onTrackingError: (target: IngestionPollingTarget, error: string) => void;
}

const isTerminal = (ingestion: Ingestion): boolean =>
  ingestion.status === INGESTION_STATUS.COMPLETED ||
  ingestion.status === INGESTION_STATUS.FAILED;

const responseError = async (
  response: Response,
  fallback: string,
): Promise<string> => {
  const payload = await response.json().catch(() => undefined);
  if (
    typeof payload === "object" &&
    payload !== null &&
    "error" in payload &&
    typeof payload.error === "string"
  ) {
    return payload.error;
  }
  return fallback;
};

export const useIngestionPolling = ({
  onCompleted,
  onFailed,
  onProgress,
  onTrackingError,
}: UseIngestionPollingOptions) => {
  const controllerRef = useRef<AbortController | null>(null);
  const dialogVisibleRef = useRef(false);
  const mountedRef = useRef(true);
  const timeoutRef = useRef<number | null>(null);

  const stop = () => {
    controllerRef.current?.abort();
    controllerRef.current = null;
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  };

  const setDialogVisible = (visible: boolean) => {
    dialogVisibleRef.current = visible;
  };

  const start = (initialTarget: IngestionPollingTarget): boolean => {
    if (!mountedRef.current) return false;
    stop();

    const controller = new AbortController();
    controllerRef.current = controller;
    let attempts = 0;
    let target = initialTarget;

    const finish = () => {
      if (controllerRef.current === controller) {
        controllerRef.current = null;
      }
      timeoutRef.current = null;
    };

    const poll = async () => {
      attempts += 1;

      try {
        const response = await fetch(`/api/ingestions/${target.ingestion.id}`, {
          signal: controller.signal,
        });
        if (!response.ok) {
          const error = await responseError(response, STATUS_ERROR);
          if (controller.signal.aborted) return;
          finish();
          onTrackingError(target, error);
          return;
        }

        const payload = (await response.json()) as {
          data?: Ingestion;
        };
        if (controller.signal.aborted) return;

        const ingestion = payload.data;
        if (!ingestion || !isTerminal(ingestion)) {
          target = {
            file: target.file,
            ingestion: ingestion ?? target.ingestion,
          };

          if (attempts >= MAX_POLL_ATTEMPTS) {
            finish();
            onTrackingError(target, STATUS_TIMEOUT);
            return;
          }

          onProgress(target);
          timeoutRef.current = window.setTimeout(
            () => void poll(),
            POLL_INTERVAL_MS,
          );
          return;
        }

        finish();
        if (ingestion.status === INGESTION_STATUS.COMPLETED) {
          onCompleted(ingestion, !dialogVisibleRef.current);
          return;
        }

        onFailed({ file: target.file, ingestion });
      } catch {
        if (controller.signal.aborted) return;
        finish();
        onTrackingError(target, STATUS_ERROR);
      }
    };

    void poll();
    return true;
  };

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      controllerRef.current?.abort();
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  return { setDialogVisible, start, stop };
};
