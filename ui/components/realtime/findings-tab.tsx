"use client";

import { CostPanel } from "@/components/realtime/cost-panel";
import { RouteBadge } from "@/components/realtime/realtime-badges";
import { RealtimeSeverity } from "@/components/realtime/realtime-severity";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeInsight } from "@/components/realtime/use-realtime-insight";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import { ROUTE_LEGEND, signalLabel } from "@/lib/realtime/display";
import {
  REALTIME_INSIGHT_KIND,
  REALTIME_ROUTE,
  type RealtimeRankedFinding,
  type RealtimeSignal,
} from "@/types/realtime";

const REFRESH_MS = 60_000;

/** What each "Handled by" badge means. */
export function RouteLegend() {
  return (
    <dl
      aria-label="Handled by legend"
      className="grid grid-cols-1 gap-x-6 gap-y-1 text-xs sm:grid-cols-2"
    >
      {Object.values(REALTIME_ROUTE).map((route) => (
        <div key={route} className="flex items-center gap-2">
          <dt>
            <RouteBadge route={route} />
          </dt>
          <dd className="text-text-neutral-tertiary">{ROUTE_LEGEND[route]}</dd>
        </div>
      ))}
    </dl>
  );
}

export function RankedFindingsTable({
  findings,
}: {
  findings: RealtimeRankedFinding[];
}) {
  if (findings.length === 0) {
    return (
      <PanelEmpty
        title="No open findings"
        description="Nothing is failing in the latest scan of this account."
      />
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <Table aria-label="Open findings ranked by likelihood of exploitation">
        <TableHeader>
          <TableRow>
            <TableHead>Score</TableHead>
            <TableHead>Finding</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Resource</TableHead>
            <TableHead>Why it ranks here</TableHead>
            <TableHead>Handled by</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((finding) => (
            <TableRow key={finding.finding_id}>
              <TableCell className="text-text-neutral-primary font-semibold tabular-nums">
                {finding.score}
              </TableCell>
              <TableCell className="max-w-72">
                <div className="flex flex-col">
                  <span className="text-text-neutral-primary">
                    {finding.title}
                  </span>
                  <code className="text-text-neutral-tertiary text-xs break-all">
                    {finding.check_id}
                  </code>
                </div>
              </TableCell>
              <TableCell>
                <RealtimeSeverity severity={finding.severity} />
              </TableCell>
              <TableCell className="max-w-56">
                <span
                  className="text-text-neutral-secondary block truncate"
                  title={finding.resource_uid}
                >
                  {finding.resource_uid}
                </span>
                {finding.region && (
                  <span className="text-text-neutral-tertiary text-xs">
                    {finding.region}
                  </span>
                )}
              </TableCell>
              <TableCell className="max-w-64">
                {finding.reasons.length > 0 ? (
                  <ul className="text-text-neutral-secondary flex flex-col gap-0.5 text-xs">
                    {finding.reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-text-neutral-tertiary text-xs">
                    Severity only
                  </span>
                )}
              </TableCell>
              <TableCell>
                <RouteBadge route={finding.route} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <RouteLegend />
    </div>
  );
}

export function SignalsList({ signals }: { signals: RealtimeSignal[] }) {
  if (signals.length === 0) {
    return (
      <PanelEmpty
        title="No suspicious activity patterns"
        description="Nothing in the last 24 hours points at a resource being used rather than just exposed."
      />
    );
  }
  return (
    <ul className="flex flex-col gap-2">
      {signals.map((signal) => (
        <li
          key={`${signal.signal}:${signal.service}:${signal.region}`}
          className="border-border-neutral-secondary flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm"
        >
          <span className="text-text-neutral-primary">
            {signalLabel(signal.signal)}
          </span>
          <span className="text-text-neutral-tertiary">
            {signal.service} in {signal.region || "global"}, {signal.count}{" "}
            event{signal.count === 1 ? "" : "s"}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function FindingsTab({
  providerId,
  demo = false,
}: {
  providerId: string;
  demo?: boolean;
}) {
  const findings = useRealtimeInsight(
    REALTIME_INSIGHT_KIND.FINDINGS,
    providerId,
    demo,
    REFRESH_MS,
  );

  return (
    <div className="flex flex-col gap-8">
      <RealtimeSection
        title="Open findings, ranked"
        description="Compliance says what is misconfigured; activity and cost say what is being used. A finding in a service showing risky activity or a cost spike moves up."
      >
        {findings.loading ? (
          <PanelLoading label="Loading findings" />
        ) : findings.failure ? (
          <PanelFailure
            failure={findings.failure}
            onRetry={findings.reload}
            subject="the ranked findings"
          />
        ) : findings.data ? (
          <RankedFindingsTable findings={findings.data.findings} />
        ) : null}
      </RealtimeSection>

      <RealtimeSection
        title="Activity signals"
        description="Patterns from the last 24 hours of CloudTrail events."
      >
        {findings.loading ? (
          <PanelLoading label="Loading signals" />
        ) : findings.failure ? (
          <PanelFailure
            failure={findings.failure}
            onRetry={findings.reload}
            subject="the activity signals"
          />
        ) : findings.data ? (
          <SignalsList signals={findings.data.signals} />
        ) : null}
      </RealtimeSection>

      <CostPanel providerId={providerId} demo={demo} />
    </div>
  );
}
