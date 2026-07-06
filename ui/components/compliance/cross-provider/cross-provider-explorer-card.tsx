"use client";

import { Maximize2, Minimize2, X } from "lucide-react";
import { useCallback, useMemo, useState } from "react";

import type { LatestCrossProviderPdfReport } from "@/actions/compliances";
import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/shadcn/accordion";
import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { EnhancedMultiSelect } from "@/components/shadcn/select/enhanced-multi-select";
import { DataTableSearch } from "@/components/ui/table/data-table-search";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { crossProviderToMapperInput } from "@/lib/compliance/cross-provider-adapter";
import type { CrossProviderInsights } from "@/lib/compliance/cross-provider-insights";
import { cn } from "@/lib/utils";
import type {
  CrossProviderComplianceOverviewAttributes,
  CrossProviderRequirement,
  CrossProviderRequirementStatus,
  Requirement,
} from "@/types/compliance";

import { CrossProviderDomainTitle } from "./cross-provider-domain-title";
import { GeneratePdfButton } from "./generate-pdf-button";

interface CrossProviderExplorerCardProps {
  attributes: CrossProviderComplianceOverviewAttributes;
  insights: CrossProviderInsights;
  /** Section key (``${frameworkName}-${categoryName}``) the orchestrator
   *  wants forced-open. Driven by the "Top Failing Domains" panel so a
   *  click expands and scrolls to the target row. */
  forcedExpandedSectionKey?: string | null;
  /** Raw ``filter[provider_type__in]`` / ``filter[provider_id__in]`` /
   *  ``filter[provider_groups__in]`` values currently applied via
   *  ``CrossProviderFilters`` — threaded through to ``GeneratePdfButton``
   *  so the generated PDF respects the same narrowing as the on-screen
   *  view. */
  providerTypeFilter?: string;
  providerIdFilter?: string;
  providerGroupsFilter?: string;
  /** A previously-generated PDF matching the current filters, resolved
   *  server-side — ``null`` means "Generate PDF" should show, not
   *  "Download PDF". */
  latestPdfReport: LatestCrossProviderPdfReport | null;
}

const STATUS_OPTIONS: Array<{
  label: string;
  value: CrossProviderRequirementStatus;
}> = [
  { label: "Failing", value: "FAIL" },
  { label: "Passing", value: "PASS" },
  { label: "Manual", value: "MANUAL" },
];

/**
 * One-stop explorer panel for a universal compliance framework. Wraps:
 *
 *   - ``DataTableSearch`` (the same search component used by the per-scan
 *     compliance grid).
 *   - ``EnhancedMultiSelect`` for status quick-filters (no custom toggle
 *     pills — same component as roles/groups/findings forms).
 *   - Expand-all toggle that flips between expanding every section and
 *     collapsing back to user-selected state.
 *   - A shadcn ``Accordion`` (type=multiple) hosting Framework →
 *     Section → Requirement.
 *
 * The card owns the controlled state for search/filters/expansion so
 * the orchestrator only feeds it ``attributes`` + ``insights`` plus an
 * optional ``forcedExpandedSectionKey`` for the Top Failing Domains
 * deep-link.
 */
export const CrossProviderExplorerCard = ({
  attributes,
  insights,
  forcedExpandedSectionKey,
  providerTypeFilter,
  providerIdFilter,
  providerGroupsFilter,
  latestPdfReport,
}: CrossProviderExplorerCardProps) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [searchKey, setSearchKey] = useState(0);
  const [statusFilters, setStatusFilters] = useState<
    CrossProviderRequirementStatus[]
  >([]);
  const [openSectionKeys, setOpenSectionKeys] = useState<string[]>([]);
  const [allSectionsOpen, setAllSectionsOpen] = useState(false);

  // Filtered attributes drive both the match counter and the accordion
  // content. The unfiltered ``insights`` continue to feed the heatmap
  // matrix per section so global counts stay stable while the user
  // narrows their search.
  const filteredAttributes = useMemo(() => {
    const lowerTerm = searchTerm.trim().toLowerCase();
    if (lowerTerm === "" && statusFilters.length === 0) {
      return attributes;
    }
    const statusSet = new Set(statusFilters);
    const filteredRequirements = attributes.requirements.filter((req) => {
      if (statusSet.size > 0 && !statusSet.has(req.status)) return false;
      if (lowerTerm === "") return true;
      const haystack =
        `${req.id} ${req.name ?? ""} ${req.description ?? ""}`.toLowerCase();
      return haystack.includes(lowerTerm);
    });
    return { ...attributes, requirements: filteredRequirements };
  }, [attributes, searchTerm, statusFilters]);

  const matchCount = filteredAttributes.requirements.length;
  const totalCount = attributes.requirements.length;
  const hasFilters = searchTerm.length > 0 || statusFilters.length > 0;

  // Frameworks / categories / requirements derived from the mapper. We
  // run this against the *filtered* attribute set so the list shrinks
  // as the user types — sections with no surviving requirements
  // disappear entirely instead of expanding to an empty body.
  const { sections, allSectionKeys, statsByName } = useMemo(() => {
    const mapper = getComplianceMapper(filteredAttributes.framework);
    const { attributesData, requirementsData } =
      crossProviderToMapperInput(filteredAttributes);
    const frameworks = mapper.mapComplianceData(
      attributesData,
      requirementsData,
    );
    const stats = new Map(insights.domainStats.map((d) => [d.name, d]));
    const allSections = frameworks.flatMap((fw) =>
      fw.categories.map((category) => {
        const requirements = category.controls.flatMap(
          (control) => control.requirements,
        );
        return {
          key: `${fw.name}-${category.name}`,
          frameworkName: fw.name,
          categoryName: category.name,
          requirements,
        };
      }),
    );
    return {
      sections: allSections,
      allSectionKeys: allSections.map((s) => s.key),
      statsByName: stats,
    };
  }, [filteredAttributes, insights]);

  const expandedKeys = useMemo(() => {
    if (allSectionsOpen) return allSectionKeys;
    const merged = new Set(openSectionKeys);
    if (forcedExpandedSectionKey) merged.add(forcedExpandedSectionKey);
    return Array.from(merged);
  }, [
    allSectionsOpen,
    allSectionKeys,
    openSectionKeys,
    forcedExpandedSectionKey,
  ]);

  const handleAccordionChange = useCallback((next: string[]) => {
    // Manually expanding/collapsing exits "all open" mode so the
    // user's last interaction is the source of truth.
    setAllSectionsOpen(false);
    setOpenSectionKeys(next);
  }, []);

  const handleToggleAll = useCallback(() => {
    setAllSectionsOpen((prev) => {
      const next = !prev;
      setOpenSectionKeys(next ? allSectionKeys : []);
      return next;
    });
  }, [allSectionKeys]);

  const handleResetFilters = useCallback(() => {
    setSearchTerm("");
    // Cycling the controlled-input key flushes ``DataTableSearch``'s
    // internal debounce so a stale keystroke doesn't fire on top of
    // the just-cleared term.
    setSearchKey((k) => k + 1);
    setStatusFilters([]);
  }, []);

  return (
    <Card variant="base" padding="md">
      <CardContent className="flex w-full min-w-0 flex-col gap-4 p-0">
        {/*
          Toolbar: search on the left, filters + expand-all on the right.
          ``flex-wrap`` keeps every control inside the card on narrow
          viewports — the "Expand all" button used to overflow because
          the previous ``flex-row`` had no wrap fallback.
        */}
        <div className="flex w-full min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <DataTableSearch
              key={searchKey}
              controlledValue={searchTerm}
              onSearchChange={setSearchTerm}
              placeholder="Search requirements by id, name or description..."
            />
            <span className="text-text-neutral-secondary shrink-0 font-mono text-xs tabular-nums">
              {matchCount}/{totalCount}
            </span>
          </div>
          {/*
            Right-hand block stays cohesive: Expand-all sits immediately
            before the status multiselect so the user reads the action
            ("expand") next to the data scope it acts on ("statuses").
            The whole block wraps to a new row as a unit when the
            viewport is narrow — never the Expand-all on its own.

            ``min-w-0`` + ``max-w-full`` on the inner block make sure
            the multiselect (which has an intrinsic min-width) stays
            inside the Card padding instead of bleeding past the
            right border on intermediate viewports.
          */}
          <div className="ml-auto flex max-w-full min-w-0 shrink-0 flex-wrap items-center justify-end gap-2">
            <GeneratePdfButton
              complianceId={attributes.compliance_id}
              scanIds={attributes.scan_ids}
              providerTypes={providerTypeFilter}
              providerIds={providerIdFilter}
              providerGroups={providerGroupsFilter}
              latestPdfReport={latestPdfReport}
              frameworkLabel={
                attributes.name ||
                attributes.framework ||
                attributes.compliance_id
              }
            />
            <Button
              variant="ghost"
              size="sm"
              onClick={handleToggleAll}
              aria-label={allSectionsOpen ? "Collapse all" : "Expand all"}
              aria-expanded={allSectionsOpen}
              className="h-8 px-2 text-xs"
            >
              {allSectionsOpen ? (
                <Minimize2 className="size-3" />
              ) : (
                <Maximize2 className="size-3" />
              )}
              {allSectionsOpen ? "Collapse all" : "Expand all"}
            </Button>
            <EnhancedMultiSelect
              options={STATUS_OPTIONS}
              defaultValue={statusFilters}
              onValueChange={(next) =>
                setStatusFilters(next as CrossProviderRequirementStatus[])
              }
              placeholder="All statuses"
              hideSelectAll
              maxCount={3}
              searchable={false}
              className="w-[180px] max-w-full"
              aria-label="Filter requirements by status"
            />
            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleResetFilters}
                className="h-8 px-2 text-xs"
              >
                <X className="size-3" />
                Reset
              </Button>
            )}
          </div>
        </div>

        {sections.length === 0 ? (
          <div className="text-text-neutral-secondary py-6 text-center text-sm italic">
            No requirements match the current filters.
          </div>
        ) : (
          <Accordion
            type="multiple"
            value={expandedKeys}
            onValueChange={handleAccordionChange}
            className="border-border-neutral-secondary divide-border-neutral-secondary divide-y rounded-md border"
          >
            {sections.map((section) => {
              const stats = statsByName.get(section.categoryName);
              return (
                <AccordionItem
                  key={section.key}
                  value={section.key}
                  className="px-3"
                >
                  <AccordionTrigger
                    className={cn(
                      "py-3",
                      forcedExpandedSectionKey === section.key &&
                        "data-[flash=1]:bg-bg-fail/10",
                    )}
                  >
                    {stats ? (
                      <CrossProviderDomainTitle
                        name={section.categoryName}
                        stats={stats}
                        providers={insights.scannedProviders}
                      />
                    ) : (
                      <span>{section.categoryName}</span>
                    )}
                  </AccordionTrigger>
                  <AccordionContent>
                    <SectionRequirements
                      sectionKey={section.key}
                      framework={attributes.framework}
                      requirements={section.requirements}
                    />
                  </AccordionContent>
                </AccordionItem>
              );
            })}
          </Accordion>
        )}
      </CardContent>
    </Card>
  );
};

interface SectionRequirementsProps {
  sectionKey: string;
  framework: string;
  requirements: Requirement[];
}

/** Inner accordion for the requirements of a section. Reuses
 *  ``ClientAccordionContent`` (the same expand body the per-scan tab
 *  renders) so per-provider breakdown table, checks list and findings
 *  table behave identically across both tabs. */
const SectionRequirements = ({
  sectionKey,
  framework,
  requirements,
}: SectionRequirementsProps) => {
  if (requirements.length === 0) return null;
  return (
    <Accordion type="multiple" className="flex flex-col">
      {requirements.map((requirement, idx) => {
        const xprov = requirement as CrossProviderRequirement;
        const itemKey = `${sectionKey}-req-${idx}`;
        return (
          <AccordionItem
            key={itemKey}
            value={itemKey}
            className="border-border-neutral-secondary border-t first:border-t-0"
          >
            <AccordionTrigger className="px-1 py-2">
              <ComplianceAccordionRequirementTitle
                type=""
                name={requirement.name}
                status={requirement.status as FindingStatus}
                providers={xprov.providers}
              />
            </AccordionTrigger>
            <AccordionContent className="px-1">
              <ClientAccordionContent
                requirement={requirement}
                scanId=""
                framework={framework}
                disableFindings={
                  requirement.check_ids.length === 0 && requirement.manual === 0
                }
              />
            </AccordionContent>
          </AccordionItem>
        );
      })}
    </Accordion>
  );
};
