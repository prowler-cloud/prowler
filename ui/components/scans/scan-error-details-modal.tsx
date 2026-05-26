"use client";

import type { ScanErrorDetails } from "@/actions/task/task.adapter";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";

export type ScanErrorDetailsState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "loaded"; details: ScanErrorDetails };

interface ScanErrorDetailsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  state: ScanErrorDetailsState;
}

function LoadedView({ details }: { details: ScanErrorDetails }) {
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <p className="text-text-neutral-tertiary text-xs font-medium">
            Error Type
          </p>
          <p className="text-text-neutral-primary text-sm font-medium break-all">
            {details.type}
          </p>
        </div>
        {details.module && (
          <div className="space-y-1">
            <p className="text-text-neutral-tertiary text-xs font-medium">
              Module
            </p>
            <p className="text-text-neutral-primary text-sm break-all">
              {details.module}
            </p>
          </div>
        )}
      </div>

      <div className="space-y-2">
        <p className="text-text-neutral-tertiary text-xs font-medium">Error</p>
        <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary max-h-72 overflow-auto rounded-md border p-3">
          {details.messages.map((message, index) => (
            <p
              key={`${message}-${index}`}
              className="text-text-neutral-primary text-sm break-words whitespace-pre-wrap"
            >
              {message}
            </p>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ScanErrorDetailsModal({
  open,
  onOpenChange,
  state,
}: ScanErrorDetailsModalProps) {
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Scan error details"
      description="Failure details returned by the scan task."
      size="2xl"
    >
      {state.kind === "loading" && (
        <p className="text-text-neutral-secondary text-sm">
          Loading error details...
        </p>
      )}

      {state.kind === "error" && (
        <div className="border-border-error-primary bg-bg-fail-secondary text-text-error-primary rounded-md border p-3 text-sm">
          {state.message}
        </div>
      )}

      {state.kind === "loaded" && <LoadedView details={state.details} />}

      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button
          type="button"
          variant="outline"
          onClick={() => onOpenChange(false)}
        >
          Close
        </Button>
        {state.kind === "loaded" && (
          <CodeSnippet
            value={state.details.copyValue}
            hideCode
            ariaLabel="Copy error details"
            className="h-9 px-3"
          />
        )}
      </div>
    </Modal>
  );
}
