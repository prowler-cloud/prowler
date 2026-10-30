import { type ReactNode } from "react";

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
      <div className="flex flex-col gap-6 lg:flex-row lg:flex-wrap lg:items-stretch">
        {threatScore}
        {exploitability}
        {checkFindings}
        {riskSeverity}
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
