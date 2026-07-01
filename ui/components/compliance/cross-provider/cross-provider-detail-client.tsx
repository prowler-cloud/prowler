"use client";

import { useCallback, useMemo, useRef, useState } from "react";

import { computeCrossProviderInsights } from "@/lib/compliance/cross-provider-insights";
import type { CrossProviderComplianceOverviewAttributes } from "@/types/compliance";

import { CrossProviderExplorerCard } from "./cross-provider-explorer-card";
import { CrossProviderHeader } from "./cross-provider-header";

interface CrossProviderDetailClientProps {
  attributes: CrossProviderComplianceOverviewAttributes;
}

/**
 * Client orchestrator that wires the redesigned 3-pane header to the
 * explorer card hosting search + multiselect status + expand-all +
 * shadcn accordion.
 *
 * Owns:
 *   - Memoised insights derived from the API response so the header
 *     and the accordion read pre-computed domain stats, score,
 *     provider coverage and top-failing rankings without re-iterating
 *     ``requirements`` themselves.
 *   - ``handleDomainSelect`` which turns a "Top Failing Domains" click into
 *     a forced-open section plus a scroll + flash on the matching anchor.
 *     Because it is a user action, the DOM work happens in the handler (a
 *     single ``requestAnimationFrame`` after the state update lets the
 *     target section commit) — not in a render-time effect.
 *
 * Drill-down stays inline (matching the per-scan compliance UX) so
 * users get the same interaction across both tabs.
 */
export const CrossProviderDetailClient = ({
  attributes,
}: CrossProviderDetailClientProps) => {
  const insights = useMemo(
    () => computeCrossProviderInsights(attributes),
    [attributes],
  );

  const accordionContainerRef = useRef<HTMLDivElement>(null);
  const flashTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [forcedExpandedSectionKey, setForcedExpandedSectionKey] = useState<
    string | null
  >(null);

  const handleDomainSelect = useCallback(
    (domainName: string) => {
      // Setting the forced key expands the target section. Selecting a domain
      // is a user action, so the scroll + flash run here (not in a reactive
      // effect): a single rAF lets the expansion commit before we locate the
      // anchor and bring it into view.
      setForcedExpandedSectionKey(`${attributes.framework}-${domainName}`);

      requestAnimationFrame(() => {
        const container = accordionContainerRef.current;
        if (!container) return;
        const anchor = container.querySelector(
          `[data-domain-anchor="${CSS.escape(domainName)}"]`,
        );
        if (!(anchor instanceof HTMLElement)) return;
        anchor.scrollIntoView({ behavior: "smooth", block: "start" });
        anchor.dataset.flash = "1";
        if (flashTimeoutRef.current) clearTimeout(flashTimeoutRef.current);
        flashTimeoutRef.current = setTimeout(() => {
          delete anchor.dataset.flash;
          flashTimeoutRef.current = null;
        }, 1200);
      });
    },
    [attributes.framework],
  );

  return (
    <div className="flex flex-col gap-6">
      <CrossProviderHeader
        framework={attributes.framework}
        name={attributes.name}
        version={attributes.version}
        description={attributes.description}
        insights={insights}
        onDomainSelect={handleDomainSelect}
      />

      <div ref={accordionContainerRef}>
        <CrossProviderExplorerCard
          attributes={attributes}
          insights={insights}
          forcedExpandedSectionKey={forcedExpandedSectionKey}
        />
      </div>
    </div>
  );
};
