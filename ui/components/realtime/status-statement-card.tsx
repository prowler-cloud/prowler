"use client";

import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeInsight } from "@/components/realtime/use-realtime-insight";
import { Button } from "@/components/shadcn/button/button";
import { useToast } from "@/components/shadcn/toast";
import { modeLabel } from "@/lib/realtime/display";
import { statementToJson, statementFilename } from "@/lib/realtime/statement";
import {
  REALTIME_INSIGHT_KIND,
  type RealtimeStatusPayload,
} from "@/types/realtime";

export function StatementBody({
  statement,
}: {
  statement: RealtimeStatusPayload;
}) {
  const { toast } = useToast();
  const json = statementToJson(statement);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(json);
      toast({ title: "Statement copied" });
    } catch {
      toast({
        variant: "destructive",
        title: "Could not copy",
        description: "Select the text and copy it, or download the file.",
      });
    }
  };

  const download = () => {
    const url = URL.createObjectURL(
      new Blob([json], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = statementFilename(statement);
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-4">
      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {[
          ["Date", statement.generated_on],
          [
            "Mode",
            statement.mode === "off" ? "No policy" : modeLabel(statement.mode),
          ],
          ["Scope", statement.scope],
          ["Checks passing", String(statement.checks_passing)],
          ["Checks failing", String(statement.checks_failing)],
          [
            "Fixed and verified, last 30 days",
            String(statement.fixed_and_verified_last_30_days),
          ],
        ].map(([label, value]) => (
          <div key={label} className="flex flex-col">
            <dt className="text-text-neutral-tertiary text-xs">{label}</dt>
            <dd className="text-text-neutral-primary text-sm font-medium">
              {value}
            </dd>
          </div>
        ))}
      </dl>
      <div className="flex flex-col gap-1">
        <span className="text-text-neutral-tertiary text-xs">
          SHA-256 stamp
        </span>
        <code className="text-text-neutral-secondary text-xs break-all">
          {statement.sha256}
        </code>
      </div>
      <pre
        tabIndex={0}
        aria-label="Status statement as JSON"
        className="bg-bg-neutral-tertiary text-text-neutral-secondary max-h-80 overflow-auto rounded-lg p-4 text-xs"
      >
        {json}
      </pre>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => void copy()}>
          Copy JSON
        </Button>
        <Button variant="outline" onClick={download}>
          Download JSON
        </Button>
      </div>
    </div>
  );
}

/** The redacted, hash-stamped statement a third party can hold. */
export function StatusStatementCard({
  providerId,
  demo = false,
}: {
  providerId: string;
  demo?: boolean;
}) {
  const status = useRealtimeInsight(
    REALTIME_INSIGHT_KIND.STATUS,
    providerId,
    demo,
  );
  return (
    <RealtimeSection
      title="Status statement"
      description="Counts only: no account ids, resources or people. The SHA-256 stamp covers every other field, so a change to the statement is detectable."
    >
      {status.loading ? (
        <PanelLoading label="Loading the statement" />
      ) : status.failure ? (
        <PanelFailure
          failure={status.failure}
          onRetry={status.reload}
          subject="the statement"
        />
      ) : status.data ? (
        <StatementBody statement={status.data} />
      ) : null}
    </RealtimeSection>
  );
}
