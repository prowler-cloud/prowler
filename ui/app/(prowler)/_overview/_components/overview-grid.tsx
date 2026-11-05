import { type ReactNode } from "react";

import { cn } from "@/lib/utils";

interface OverviewGridProps {
  threatScore: ReactNode;
  // Cloud-only widgets: the page leaves them out where they do not apply.
  exploitability?: ReactNode;
  topIssues?: ReactNode;
  checkFindings: ReactNode;
  riskSeverity: ReactNode;
  resourcesInventory: ReactNode;
  complianceWatchlist: ReactNode;
  serviceWatchlist: ReactNode;
  attackSurface: ReactNode;
  severityOverTime: ReactNode;
  graphsTabs: ReactNode;
}

/** The Overview widget layout, shared by the real page and the sample preview. */
export function OverviewGrid({
  threatScore,
  exploitability,
  topIssues,
  checkFindings,
  riskSeverity,
  resourcesInventory,
  complianceWatchlist,
  serviceWatchlist,
  attackSurface,
  severityOverTime,
  graphsTabs,
}: OverviewGridProps) {
  return (
    <>
      {/* The grid owns every card width, so no row ever leaves a hole: two
          even columns on tablets, then every card in one row. Narrow cards
          take 5 parts to the wide cards' 7, never under the 17rem the
          ThreatScore gauge needs. */}
      <div
        className={cn(
          "grid grid-cols-1 gap-6 sm:grid-cols-2",
          exploitability
            ? "@min-[72rem]:grid-cols-[minmax(17rem,5fr)_minmax(17rem,5fr)_minmax(0,7fr)_minmax(0,7fr)]"
            : "lg:grid-cols-[minmax(17rem,5fr)_minmax(0,7fr)_minmax(0,7fr)]",
        )}
      >
        {threatScore}
        {exploitability}
        {checkFindings}
        {/* Without Exploitability three cards share two columns: Risk Severity
            takes the full row, as a bar chart reads well wide. */}
        <div
          className={cn(
            "grid min-w-0",
            !exploitability && "sm:col-span-2 lg:col-span-1",
          )}
        >
          {riskSeverity}
        </div>
      </div>

      <div className="mt-6">{resourcesInventory}</div>

      <div className="mt-6 flex flex-col gap-6 xl:flex-row">
        {/* Watchlists: stacked on mobile, row on tablet, stacked on desktop */}
        {/* No `flex-wrap` here: a multi-line flex container sizes its items to
            the line's max-content rather than to its own 312px, and a card wider
            than the column loses its right border and padding to
            `overflow-hidden`. It never wrapped anyway. */}
        <div className="flex min-w-0 flex-col gap-6 overflow-hidden sm:flex-row sm:items-stretch xl:w-[312px] xl:shrink-0 xl:flex-col">
          {/* Sized to its own list, unlike the service card below: this one is
              as long as the organization made its watchlist, so growing it to
              fill the column puts a hole under two pinned frameworks. */}
          {/* `h-full` only where the cards sit side by side and share a row
              height. In the column it would hand the card the stretched
              wrapper's height and undo the fit-to-content sizing. */}
          <div className="min-w-0 sm:flex-1 xl:flex-none sm:[&>*]:h-full xl:[&>*]:h-auto">
            {complianceWatchlist}
          </div>
          <div className="min-w-0 sm:flex-1 xl:flex-auto [&>*]:h-full">
            {serviceWatchlist}
          </div>
        </div>

        {/* Charts column: Attack Surface, Top issues, Findings Over Time */}
        <div className="flex flex-1 flex-col gap-6">
          {attackSurface}
          {topIssues}
          {severityOverTime}
        </div>
      </div>

      <div className="mt-6">{graphsTabs}</div>
    </>
  );
}
