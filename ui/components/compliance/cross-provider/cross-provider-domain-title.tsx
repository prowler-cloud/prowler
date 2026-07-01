"use client";

import type {
  DomainProviderStatus,
  DomainStats,
} from "@/lib/compliance/cross-provider-insights";
import {
  getProviderBadge,
  getProviderLabel,
} from "@/lib/providers/provider-display";
import { cn } from "@/lib/utils";

const HEATMAP_CELL_BY_STATUS: Record<DomainProviderStatus, string> = {
  PASS: "bg-bg-pass border-bg-pass",
  FAIL: "bg-bg-fail border-bg-fail",
  MANUAL: "bg-bg-warning/70 border-bg-warning",
  NO_ROW: "bg-default-200 border-border-neutral-secondary opacity-40",
};

const STRIPE_CLASS_BY_DOMINANT = (stats: DomainStats): string => {
  if (stats.fail > 0) return "bg-bg-fail";
  if (stats.pass > 0) return "bg-bg-pass";
  if (stats.manual > 0) return "bg-bg-warning";
  return "bg-default-300";
};

interface CrossProviderDomainTitleProps {
  name: string;
  stats: DomainStats;
  compatibleProviders: string[];
}

/**
 * Domain (section) row title that surfaces the per-provider heatmap and
 * an at-a-glance failure stripe so the user can read 17 rows in one
 * pass instead of expanding each one.
 *
 * Layout: [colored stripe] [domain name] [heatmap matrix] [stack bar]
 * [counts]. The stripe color reflects worst-case status (fail > pass >
 * manual > no-row); the heatmap matrix shows one cell per compatible
 * provider — dimmed for non-contributing ones — with the precise
 * rolled-up status surfaced via the native ``title`` attribute. We
 * deliberately avoid Radix Tooltip here: 5 providers × 17 sections =
 * 85 cells per page would mount 85 ``TooltipProvider`` + ``Root``
 * pairs on initial render.
 */
export const CrossProviderDomainTitle = ({
  name,
  stats,
  compatibleProviders,
}: CrossProviderDomainTitleProps) => {
  const total = Math.max(stats.total, 1);
  const passPct = (stats.pass / total) * 100;
  const failPct = (stats.fail / total) * 100;
  const manualPct = (stats.manual / total) * 100;

  return (
    <div
      data-domain-anchor={name}
      className="data-[flash=1]:bg-bg-fail/10 flex w-full items-stretch gap-3 transition-colors"
    >
      <div
        className={cn(
          "w-1 shrink-0 rounded-sm",
          STRIPE_CLASS_BY_DOMINANT(stats),
        )}
        aria-hidden="true"
      />
      <div className="flex w-full min-w-0 flex-wrap items-center gap-3 py-1">
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="text-text-default truncate text-sm font-semibold">
            {name}
          </span>
          <span className="text-text-neutral-secondary mt-0.5 font-mono text-[10px]">
            {stats.total} {stats.total === 1 ? "requirement" : "requirements"}
          </span>
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          {compatibleProviders.map((providerKey) => {
            const status: DomainProviderStatus =
              stats.byProvider[providerKey] ?? "NO_ROW";
            const Badge = getProviderBadge(providerKey);
            const label = getProviderLabel(providerKey);
            const tooltip = `${label}: ${status === "NO_ROW" ? "no scan" : status}`;
            return (
              <span
                key={providerKey}
                title={tooltip}
                aria-label={tooltip}
                className={cn(
                  "flex size-5 items-center justify-center rounded border",
                  HEATMAP_CELL_BY_STATUS[status],
                )}
              >
                {Badge ? <Badge size={12} className="opacity-90" /> : null}
              </span>
            );
          })}
        </div>

        <div className="bg-default-200 dark:bg-default-100/30 flex h-1.5 w-32 shrink-0 overflow-hidden rounded-full sm:w-44">
          {stats.pass > 0 && (
            <span
              className="bg-bg-pass h-full"
              style={{ width: `${passPct}%` }}
            />
          )}
          {stats.fail > 0 && (
            <span
              className="bg-bg-fail h-full"
              style={{ width: `${failPct}%` }}
            />
          )}
          {stats.manual > 0 && (
            <span
              className="bg-bg-warning h-full"
              style={{ width: `${manualPct}%` }}
            />
          )}
        </div>

        <div className="text-text-neutral-secondary flex shrink-0 items-center gap-2 font-mono text-[11px] tabular-nums">
          <span className="text-bg-pass">{stats.pass}</span>
          <span aria-hidden="true">·</span>
          <span className="text-bg-fail">{stats.fail}</span>
          <span aria-hidden="true">·</span>
          <span className="text-bg-warning">{stats.manual}</span>
        </div>
      </div>
    </div>
  );
};
