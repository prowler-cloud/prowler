"use client";

import { Check, Slash } from "lucide-react";

import type { ProviderCoverage } from "@/lib/compliance/cross-provider-insights";
import {
  getProviderBadge,
  getProviderLabel,
} from "@/lib/providers/provider-display";
import { cn } from "@/lib/utils";

interface ProviderCoveragePanelProps {
  coverage: ProviderCoverage[];
}

/**
 * Right-of-score panel listing every compatible provider with its
 * per-provider score and a clear "scan available" / "no scan yet"
 * marker. Keeps non-contributing providers visible (dimmed) instead of
 * hiding them — the user needs to know coverage gaps as much as
 * coverage itself.
 */
export const ProviderCoveragePanel = ({
  coverage,
}: ProviderCoveragePanelProps) => {
  return (
    <div className="flex h-full flex-col gap-3">
      <h3 className="text-text-neutral-secondary text-[11px] font-semibold tracking-wider uppercase">
        Provider Coverage
      </h3>
      <ul className="flex flex-col gap-2">
        {coverage.map((entry) => {
          const Badge = getProviderBadge(entry.key);
          const label = getProviderLabel(entry.key);
          const Icon = entry.contributing ? Check : Slash;
          const dimmed = !entry.contributing;
          return (
            <li
              key={entry.key}
              className={cn(
                "border-border-neutral-secondary flex items-center gap-3 rounded-md border px-3 py-2",
                dimmed && "opacity-60",
              )}
            >
              {Badge ? <Badge size={20} /> : null}
              <div className="flex min-w-0 flex-1 flex-col gap-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-text-default flex min-w-0 items-baseline gap-1.5 truncate text-xs font-semibold">
                    {label}
                    {entry.accountCount > 1 && (
                      <span className="text-text-neutral-secondary text-[10px] font-medium tracking-wider uppercase">
                        {entry.accountCount} accounts
                      </span>
                    )}
                  </span>
                  {entry.contributing ? (
                    <span className="font-mono text-xs font-bold tabular-nums">
                      {entry.scorePercent}%
                    </span>
                  ) : (
                    <span className="text-text-neutral-secondary text-[10px] tracking-wider uppercase">
                      No scan
                    </span>
                  )}
                </div>
                <div className="bg-default-200 dark:bg-default-100/30 h-1.5 w-full overflow-hidden rounded-full">
                  {entry.contributing && entry.total > 0 ? (
                    <div
                      className="bg-bg-pass h-full"
                      style={{ width: `${entry.scorePercent}%` }}
                    />
                  ) : null}
                </div>
                {entry.contributing && (
                  <span className="text-text-neutral-secondary font-mono text-[10px]">
                    {entry.pass} / {entry.total} pass
                    {entry.fail > 0 && (
                      <span className="text-bg-fail ml-2">
                        {entry.fail} fail
                      </span>
                    )}
                  </span>
                )}
              </div>
              <Icon
                className={cn(
                  "size-4 shrink-0",
                  entry.contributing
                    ? "text-bg-pass"
                    : "text-text-neutral-secondary",
                )}
                strokeWidth={entry.contributing ? 3 : 2}
                aria-hidden="true"
              />
            </li>
          );
        })}
      </ul>
    </div>
  );
};
