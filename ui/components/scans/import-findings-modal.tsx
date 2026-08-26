"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import { FileUploadDropzone } from "@/components/shadcn/file-upload/file-upload-dropzone";
import { Modal } from "@/components/shadcn/modal/modal";
import { useToast } from "@/components/shadcn/toast/use-toast";
import type { Ingestion, IngestionResponse } from "@/types";

const POLL_INTERVAL_MS = 5000;

const IMPORT_STATE = {
  IDLE: "idle",
  READY: "ready",
  UPLOADING: "uploading",
  TRACKING: "tracking",
  TRACKING_ERROR: "tracking-error",
  COMPLETED: "completed",
  FAILED: "failed",
  INVALID: "invalid",
} as const;

interface IdleImportState {
  type: typeof IMPORT_STATE.IDLE;
}

interface ReadyImportState {
  type: typeof IMPORT_STATE.READY;
  file: File;
}

interface UploadingImportState {
  type: typeof IMPORT_STATE.UPLOADING;
  file: File;
}

interface TrackingImportState {
  type: typeof IMPORT_STATE.TRACKING;
  file: File;
  ingestion: Ingestion;
}

interface TrackingErrorImportState {
  type: typeof IMPORT_STATE.TRACKING_ERROR;
  error: string;
  file: File;
  ingestion: Ingestion;
}

interface CompletedImportState {
  type: typeof IMPORT_STATE.COMPLETED;
  ingestion: Ingestion;
}

interface FailedImportState {
  type: typeof IMPORT_STATE.FAILED;
  error: string;
  file: File;
  // Only a terminal `failed` job reports counters; a rejected upload never
  // became one, so it has nothing to summarise.
  ingestion?: Ingestion;
}

interface InvalidImportState {
  type: typeof IMPORT_STATE.INVALID;
  error: string;
}

type ImportState =
  | IdleImportState
  | ReadyImportState
  | UploadingImportState
  | TrackingImportState
  | TrackingErrorImportState
  | CompletedImportState
  | FailedImportState
  | InvalidImportState;

interface ImportFindingsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const isTerminal = (ingestion: Ingestion): boolean =>
  ingestion.status === "completed" || ingestion.status === "failed";

const validateFile = (file: File): string | null => {
  if (!file.name.toLowerCase().endsWith(".ocsf.json")) {
    return "Choose a Prowler .ocsf.json finding report.";
  }
  if (file.size === 0) return "The selected file is empty.";
  return null;
};

const responseError = async (response: Response): Promise<string> => {
  const payload = await response.json().catch(() => undefined);
  if (
    typeof payload === "object" &&
    payload !== null &&
    "error" in payload &&
    typeof payload.error === "string"
  ) {
    return payload.error;
  }
  return "Unable to start the import. Please try again.";
};

export function ImportFindingsModal({
  open,
  onOpenChange,
}: ImportFindingsModalProps) {
  const router = useRouter();
  const { toast } = useToast();
  const [state, setState] = useState<ImportState>({ type: IMPORT_STATE.IDLE });
  const pollAbortController = useRef<AbortController | null>(null);
  const openRef = useRef(open);
  const tracking = state.type === IMPORT_STATE.TRACKING ? state : undefined;
  const trackingId = tracking?.ingestion.id;
  const trackingRef = useRef(tracking);
  trackingRef.current = tracking;

  useEffect(() => {
    openRef.current = open;
  }, [open]);

  useEffect(() => {
    if (!trackingId) return;

    const controller = new AbortController();
    pollAbortController.current = controller;
    let timeout: number | undefined;

    const poll = async () => {
      const activeTracking = trackingRef.current;
      if (!activeTracking) return;

      try {
        const response = await fetch(`/api/ingestions/${trackingId}`, {
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(await responseError(response));
        }

        const payload = (await response.json()) as IngestionResponse;
        const ingestion = payload.data;
        if (!ingestion || !isTerminal(ingestion)) {
          setState({
            type: IMPORT_STATE.TRACKING,
            file: activeTracking.file,
            ingestion,
          });
          timeout = window.setTimeout(() => void poll(), POLL_INTERVAL_MS);
          return;
        }

        if (ingestion.status === "completed") {
          router.refresh();
          if (!openRef.current) {
            toast({
              title: "Findings import completed",
              description: "Imported findings are now available in Scans.",
            });
          }
          setState({ type: IMPORT_STATE.COMPLETED, ingestion });
          return;
        }

        setState({
          type: IMPORT_STATE.FAILED,
          error:
            "Import failed. Retry the same file or select a different report.",
          file: activeTracking.file,
          ingestion,
        });
      } catch (error) {
        if (controller.signal.aborted) return;
        setState({
          type: IMPORT_STATE.TRACKING_ERROR,
          error:
            error instanceof Error
              ? error.message
              : "Unable to check the import status. Please try again.",
          file: activeTracking.file,
          ingestion: activeTracking.ingestion,
        });
      }
    };

    void poll();
    return () => {
      controller.abort();
      if (timeout) window.clearTimeout(timeout);
    };
  }, [router, toast, trackingId]);

  const handleFileSelect = (file?: File) => {
    if (!file) {
      setState({ type: IMPORT_STATE.IDLE });
      return;
    }

    const error = validateFile(file);
    setState(
      error
        ? { type: IMPORT_STATE.INVALID, error }
        : { type: IMPORT_STATE.READY, file },
    );
  };

  const handleOpenChange = (nextOpen: boolean) => {
    // Dismissing never aborts the request, so an in-flight upload keeps its
    // state like tracking does: resetting here would lose the accepted job and
    // re-enable submission for a second, concurrent POST.
    if (
      !nextOpen &&
      state.type !== IMPORT_STATE.UPLOADING &&
      state.type !== IMPORT_STATE.TRACKING &&
      state.type !== IMPORT_STATE.TRACKING_ERROR
    ) {
      setState({ type: IMPORT_STATE.IDLE });
    }
    onOpenChange(nextOpen);
  };

  const upload = async (file: File) => {
    setState({ type: IMPORT_STATE.UPLOADING, file });
    const formData = new FormData();
    formData.set("file", file);
    const response = await fetch("/api/ingestions", {
      method: "POST",
      body: formData,
    }).catch(() => undefined);
    if (!response || !response.ok) {
      setState({
        type: IMPORT_STATE.FAILED,
        error: response
          ? await responseError(response)
          : "Unable to start the import. Please try again.",
        file,
      });
      return;
    }

    const payload = (await response.json()) as IngestionResponse;
    setState({ type: IMPORT_STATE.TRACKING, file, ingestion: payload.data });
  };

  const submit = async () => {
    if (state.type !== IMPORT_STATE.READY) return;
    await upload(state.file);
  };

  const file =
    state.type === IMPORT_STATE.READY ||
    state.type === IMPORT_STATE.UPLOADING ||
    state.type === IMPORT_STATE.FAILED ||
    state.type === IMPORT_STATE.TRACKING ||
    state.type === IMPORT_STATE.TRACKING_ERROR
      ? state.file
      : undefined;
  const isSubmitting = state.type === IMPORT_STATE.UPLOADING;
  const completed = state.type === IMPORT_STATE.COMPLETED;

  return (
    <Modal
      open={open}
      onOpenChange={handleOpenChange}
      title="Import findings"
      description="Upload a Prowler OCSF finding report to add it to Scans."
      size="md"
    >
      <div className="flex flex-col gap-4">
        {completed ? (
          <p>
            Import completed: {state.ingestion.totalRecords} total records,{" "}
            {state.ingestion.processedRecords} processed,{" "}
            {state.ingestion.invalidRecords} invalid.
          </p>
        ) : (
          <>
            <div data-testid="import-findings-dropzone">
              <FileUploadDropzone
                file={file}
                accept=".ocsf.json,application/json"
                onFileSelect={handleFileSelect}
                disabled={
                  isSubmitting ||
                  state.type === IMPORT_STATE.TRACKING ||
                  state.type === IMPORT_STATE.TRACKING_ERROR
                }
              />
            </div>
            {state.type === IMPORT_STATE.INVALID && (
              <p role="alert">{state.error}</p>
            )}
            {state.type === IMPORT_STATE.FAILED && (
              <>
                <p role="alert">{state.error}</p>
                {state.ingestion && (
                  <p>
                    Reported progress: {state.ingestion.processedRecords} of{" "}
                    {state.ingestion.totalRecords} records processed,{" "}
                    {state.ingestion.invalidRecords} invalid.
                  </p>
                )}
                <Button type="button" onClick={() => void upload(state.file)}>
                  Retry import
                </Button>
              </>
            )}
            {state.type === IMPORT_STATE.TRACKING && (
              <p>Import is {state.ingestion.status}.</p>
            )}
            {state.type === IMPORT_STATE.TRACKING_ERROR && (
              <>
                <p role="alert">{state.error}</p>
                <Button
                  type="button"
                  onClick={() =>
                    setState({
                      type: IMPORT_STATE.TRACKING,
                      file: state.file,
                      ingestion: state.ingestion,
                    })
                  }
                >
                  Retry status
                </Button>
              </>
            )}
            <Button
              type="button"
              onClick={() => void submit()}
              disabled={state.type !== IMPORT_STATE.READY || isSubmitting}
            >
              {isSubmitting ? "Importing..." : "Start import"}
            </Button>
          </>
        )}
      </div>
    </Modal>
  );
}
