"use client";

import type { ScanErrorDetails } from "@/actions/task/task.adapter";
import { Button, Card, CardContent } from "@/components/shadcn";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { Modal } from "@/components/shadcn/modal";
import { LoadingState } from "@/components/shadcn/spinner/loading-state";
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

function LoadingView() {
  return <LoadingState label="Loading error details..." />;
}

function ErrorView({ message }: { message: string }) {
  return (
    <Card variant="danger">
      <CardContent>
        <p className="text-text-error-primary text-sm">{message}</p>
      </CardContent>
    </Card>
  );
}

function LoadedView({ details }: { details: ScanErrorDetails }) {
  return (
    <Card variant="base" padding="lg">
      <CardContent className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Error Type">{details.type}</InfoField>
          {details.module && (
            <InfoField label="Module">{details.module}</InfoField>
          )}
        </div>
        <InfoField label="Error" variant="simple">
          <CodeSnippet
            value={details.copyValue}
            formatter={() => details.messages.join("\n")}
            multiline
            ariaLabel="Copy error details"
          />
        </InfoField>
      </CardContent>
    </Card>
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
      title="Scan Error Details"
      description="Failure details returned by the scan task."
      size="2xl"
    >
      {state.kind === "loading" && <LoadingView />}
      {state.kind === "error" && <ErrorView message={state.message} />}
      {state.kind === "loaded" && <LoadedView details={state.details} />}

      <div className="flex w-full justify-end gap-4">
        <Button
          type="button"
          variant="ghost"
          size="lg"
          onClick={() => onOpenChange(false)}
        >
          Close
        </Button>
      </div>
    </Modal>
  );
}
