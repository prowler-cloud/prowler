"use client";

import { AlertTriangle, ChevronRight } from "lucide-react";

import type { DomainStats } from "@/lib/compliance/cross-provider-insights";
import { cn } from "@/lib/utils";

interface TopFailingDomainsPanelProps {
  domains: DomainStats[];
  /** Max entries to show. Defaults to 3. */
  limit?: number;
  /** Click handler that scroll-anchors to the matching domain row. */
  onSelect?: (domainName: string) => void;
}

/**
 * Top-N failing domains as a quick teaser. Each entry is a click
 * shortcut: anchors the accordion to the corresponding section so the
 * user does not have to scroll-scan 17 domain rows to find the one
 * worth investigating first.
 *
 * When ``onSelect`` is omitted the entries render as static rows — the
 * panel is still useful as a read-only summary for screenshots and
 * exports.
 */
export const TopFailingDomainsPanel = ({
  domains,
  limit = 3,
  onSelect,
}: TopFailingDomainsPanelProps) => {
  const top = domains.filter((d) => d.fail > 0).slice(0, limit);

  return (
    <div className="flex h-full flex-col gap-3">
      <h3 className="text-text-neutral-secondary text-[11px] font-semibold tracking-wider uppercase">
        Top Failing Domains
      </h3>
      {top.length === 0 ? (
        <div className="border-border-neutral-secondary flex flex-1 items-center justify-center rounded-md border border-dashed px-3 py-6">
          <span className="text-text-neutral-secondary text-xs">
            No failing domains. Keep it up.
          </span>
        </div>
      ) : (
        <ul className="flex flex-col gap-2">
          {top.map((domain) => {
            const Tag = onSelect ? "button" : "div";
            return (
              <li key={domain.name}>
                <Tag
                  type={onSelect ? "button" : undefined}
                  onClick={onSelect ? () => onSelect(domain.name) : undefined}
                  className={cn(
                    "border-border-neutral-secondary flex w-full items-center gap-3 rounded-md border px-3 py-2 text-left transition-colors",
                    onSelect &&
                      "hover:border-bg-fail/40 hover:bg-bg-fail/5 cursor-pointer",
                  )}
                >
                  <AlertTriangle
                    className="text-bg-fail size-4 shrink-0"
                    aria-hidden="true"
                  />
                  <div className="flex min-w-0 flex-1 flex-col">
                    <span className="text-text-neutral-primary truncate text-xs font-semibold">
                      {domain.name}
                    </span>
                    <span className="text-text-neutral-secondary font-mono text-[10px]">
                      {domain.fail} fail · {domain.total} total
                    </span>
                  </div>
                  {onSelect && (
                    <ChevronRight
                      className="text-text-neutral-secondary size-3.5 shrink-0"
                      aria-hidden="true"
                    />
                  )}
                </Tag>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
};
