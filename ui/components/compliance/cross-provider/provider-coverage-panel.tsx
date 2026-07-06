"use client";

import { ProviderBadgeIcon } from "@/components/icons/providers-badge/provider-badge-icon";
import type { ProviderCoverage } from "@/lib/compliance/cross-provider-insights";
import { getProviderLabel } from "@/lib/providers/provider-display";
import { cn } from "@/lib/utils";

interface ProviderCoveragePanelProps {
  coverage: ProviderCoverage[];
}

/**
 * Right-of-score panel listing every SCANNED provider with its
 * per-provider score. In the detail view we only show providers we
 * actually have scans for — framework-compatible providers with no scan
 * belong on the overview (where they're listed dimmed as "no scan yet"),
 * not here.
 *
 * Laid out as a tile grid rather than a single-column list: universal
 * frameworks can declare 15+ compatible providers, and one row per
 * provider made this panel several screens taller than its siblings
 * (score donut, top failing domains). The account-count detail that no
 * longer fits inline moves to the tile's ``title`` tooltip.
 */
export const ProviderCoveragePanel = ({
  coverage,
}: ProviderCoveragePanelProps) => {
  return (
    <div className="flex h-full flex-col gap-3">
      <h3 className="text-text-neutral-secondary text-[11px] font-semibold tracking-wider uppercase">
        Provider Coverage
      </h3>
      {coverage.length === 0 && (
        <p className="text-text-neutral-secondary text-xs italic">
          No scanned providers for this framework yet.
        </p>
      )}
      <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {coverage.map((entry) => {
          const label = getProviderLabel(entry.key);
          const dimmed = !entry.contributing;
          const tooltip = entry.contributing
            ? `${label}: ${entry.scorePercent}% — ${entry.pass} pass / ${entry.fail} fail (${entry.total} total)` +
              (entry.accountCount > 1
                ? ` · ${entry.accountCount} accounts`
                : "")
            : `${label}: scanned, no data yet`;
          return (
            <li
              key={entry.key}
              title={tooltip}
              className={cn(
                "border-border-neutral-secondary flex flex-col gap-1.5 rounded-md border px-2.5 py-2",
                dimmed && "opacity-60",
              )}
            >
              <div className="flex items-center gap-1.5">
                <ProviderBadgeIcon providerKey={entry.key} size={16} />
                <span className="text-text-neutral-primary min-w-0 flex-1 truncate text-xs font-semibold">
                  {label}
                </span>
                {entry.contributing ? (
                  <span className="shrink-0 font-mono text-[11px] font-bold tabular-nums">
                    {entry.scorePercent}%
                  </span>
                ) : (
                  <span className="text-text-neutral-secondary shrink-0 text-[9px] font-medium tracking-wider uppercase">
                    No data
                  </span>
                )}
              </div>
              <div className="bg-default-200 dark:bg-default-100/30 h-1 w-full overflow-hidden rounded-full">
                {entry.contributing && entry.total > 0 ? (
                  <div
                    className="bg-bg-pass h-full"
                    style={{ width: `${entry.scorePercent}%` }}
                  />
                ) : null}
              </div>
              {/* Always reserve this line — even for "no scan" tiles —
                  so every tile in the grid is the same height regardless
                  of which row it lands in. */}
              <span className="text-text-neutral-secondary font-mono text-[9px]">
                {entry.contributing ? (
                  <>
                    {entry.pass}/{entry.total} pass
                    {entry.fail > 0 && (
                      <span className="text-bg-fail ml-1.5">
                        {entry.fail} fail
                      </span>
                    )}
                  </>
                ) : (
                  <>&nbsp;</>
                )}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
};
