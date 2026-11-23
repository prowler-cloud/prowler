"use client";

import { Download, FileCheck2 } from "lucide-react";
import { useState } from "react";

import {
  getRealtimeDemo,
  getRealtimeInsight,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import {
  modeLabel,
  orderedSeverities,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  statementFilename,
  statementToJson,
} from "@/app/(prowler)/realtime/_lib/statement";
import type {
  RealtimeFailure,
  RealtimeStatusPayload,
} from "@/app/(prowler)/realtime/_types";
import { Button, Skeleton } from "@/components/shadcn";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { Modal } from "@/components/shadcn/modal";

interface RealtimeShareStatusProps {
  providerId: string;
  demo: boolean;
}

type StatementState =
  | { status: "idle" | "loading" }
  | { status: "ready"; statement: RealtimeStatusPayload }
  | { status: "failed"; failure: RealtimeFailure };

const downloadJson = (statement: RealtimeStatusPayload) => {
  const blob = new Blob([statementToJson(statement)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = statementFilename(statement);
  link.click();
  URL.revokeObjectURL(url);
};

/** A redacted, hashed status statement to share with auditors or a team. */
export function RealtimeShareStatus({
  providerId,
  demo,
}: RealtimeShareStatusProps) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<StatementState>({ status: "idle" });

  const openStatement = async () => {
    setOpen(true);
    setState({ status: "loading" });
    const result = demo
      ? await getRealtimeDemo("status")
      : await getRealtimeInsight("status", providerId);
    setState(
      result.ok
        ? { status: "ready", statement: result.data }
        : { status: "failed", failure: result },
    );
  };

  const statement = state.status === "ready" ? state.statement : null;

  return (
    <>
      <Button variant="outline" onClick={openStatement}>
        <FileCheck2 aria-hidden />
        Share status
      </Button>
      <Modal
        open={open}
        onOpenChange={setOpen}
        title="Status statement"
        description="A summary with no account ids, resources or people, stamped with a SHA-256 hash of its content."
        size="lg"
      >
        {state.status === "failed" ? (
          <RealtimePanelError failure={state.failure} />
        ) : !statement ? (
          <div className="flex flex-col gap-3">
            <Skeleton className="h-28 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-3">
              <InfoField label="Date">{statement.generated_on}</InfoField>
              <InfoField label="Mode">
                {statement.mode === "off"
                  ? "No policy"
                  : modeLabel(statement.mode)}
              </InfoField>
              <InfoField label="Scope">{statement.scope}</InfoField>
              <InfoField label="Fixed and verified, last 30 days">
                {statement.fixed_and_verified_last_30_days}
              </InfoField>
              <InfoField label="Checks passing">
                {statement.checks_passing}
              </InfoField>
              <InfoField label="Checks failing">
                {statement.checks_failing}
                {orderedSeverities(statement.failing_by_severity).length
                  ? ` (${orderedSeverities(statement.failing_by_severity)
                      .map(([severity, count]) => `${count} ${severity}`)
                      .join(", ")})`
                  : ""}
              </InfoField>
            </div>
            <InfoField label="SHA-256">
              <CodeSnippet
                value={statement.sha256}
                multiline
                className="font-mono"
              />
            </InfoField>
            <div className="flex flex-wrap justify-end gap-2">
              <CodeSnippet
                value={statementToJson(statement)}
                hideCode
                ariaLabel="Copy the statement as JSON"
              />
              <Button variant="outline" onClick={() => downloadJson(statement)}>
                <Download aria-hidden />
                Download JSON
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}
