"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import { FileUploadDropzone } from "@/components/shadcn/file-upload/file-upload-dropzone";
import { Modal } from "@/components/shadcn/modal/modal";
import { useToast } from "@/components/shadcn/toast/use-toast";
import { type Ingestion, type IngestionResponse } from "@/types";

import {
  type IngestionPollingTarget,
  useIngestionPolling,
} from "./use-ingestion-polling";

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
  // Absent when the upload itself was rejected: no job, so no counters.
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

const validateFile = (file: File): string | null => {
  if (!file.name.toLowerCase().endsWith(".ocsf.json")) {
    return "Choose a Prowler .ocsf.json finding report.";
  }
  if (file.size === 0) return "The selected file is empty.";
  return null;
};

const START_ERROR = "Unable to start the import. Please try again.";

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

export function ImportFindingsModal() {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<ImportState>({ type: IMPORT_STATE.IDLE });
  const polling = useIngestionPolling({
    onCompleted: (ingestion, completedWhileHidden) => {
      router.refresh();
      if (completedWhileHidden) {
        toast({
          title: "Findings import completed",
          description: "Imported findings are now available in Scans.",
        });
      }
      setState({ type: IMPORT_STATE.COMPLETED, ingestion });
    },
    onFailed: ({ file, ingestion }) => {
      setState({
        type: IMPORT_STATE.FAILED,
        error:
          "Import failed. Retry the same file or select a different report.",
        file,
        ingestion,
      });
    },
    onProgress: ({ file, ingestion }) => {
      setState({ type: IMPORT_STATE.TRACKING, file, ingestion });
    },
    onTrackingError: ({ file, ingestion }, error) => {
      setState({
        type: IMPORT_STATE.TRACKING_ERROR,
        error,
        file,
        ingestion,
      });
    },
  });

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
    polling.setDialogVisible(nextOpen);
    // A job that completed while hidden leaves a summary nobody dismissed.
    // Reset it on the next open so the dropzone is available again.
    if (nextOpen && state.type === IMPORT_STATE.COMPLETED) {
      setState({ type: IMPORT_STATE.IDLE });
    }
    // Dismissing never aborts the request: resetting here would drop the
    // accepted job and re-enable submit for a second, concurrent POST.
    if (
      !nextOpen &&
      state.type !== IMPORT_STATE.UPLOADING &&
      state.type !== IMPORT_STATE.TRACKING &&
      state.type !== IMPORT_STATE.TRACKING_ERROR
    ) {
      setState({ type: IMPORT_STATE.IDLE });
    }
    setOpen(nextOpen);
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
          ? await responseError(response, START_ERROR)
          : START_ERROR,
        file,
      });
      return;
    }

    const payload = (await response.json()) as IngestionResponse;
    const target: IngestionPollingTarget = { file, ingestion: payload.data };
    if (!polling.start(target)) return;
    setState({ type: IMPORT_STATE.TRACKING, ...target });
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
    <>
      <Button
        type="button"
        size="lg"
        variant="secondary"
        onClick={() => handleOpenChange(true)}
        className="w-full md:w-auto"
      >
        Import Findings
      </Button>
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
                    onClick={() => {
                      const target: IngestionPollingTarget = {
                        file: state.file,
                        ingestion: state.ingestion,
                      };
                      setState({
                        type: IMPORT_STATE.TRACKING,
                        ...target,
                      });
                      polling.start(target);
                    }}
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
    </>
  );
}
