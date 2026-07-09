"use client";

import { AlertTriangle } from "lucide-react";
import { useSearchParams } from "next/navigation";

import {
  loadLatestFindingTriageNote,
  updateFindingTriage,
} from "@/actions/findings";
import {
  getStandaloneFindingColumns,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { Alert, AlertDescription, Button } from "@/components/shadcn";
import { Accordion } from "@/components/shadcn/accordion/Accordion";
import { DataTable } from "@/components/shadcn/table";
import { FINDINGS_DEFAULT_SORT, MUTED_FILTER } from "@/lib";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { shouldRefreshAfterTriageUpdate } from "@/lib/finding-triage";
import { Requirement } from "@/types/compliance";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

import { useRequirementFindings } from "./use-requirement-findings";

interface ClientAccordionContentProps {
  requirement: Requirement;
  scanId: string;
  framework: string;
  disableFindings?: boolean;
}

export const ClientAccordionContent = ({
  requirement,
  framework,
  scanId,
  disableFindings = false,
}: ClientAccordionContentProps) => {
  const searchParams = useSearchParams();
  const pageNumber = searchParams.get("page") || "1";
  const pageSize = searchParams.get("pageSize") || "10";
  const complianceId = searchParams.get("complianceId");
  const openFindingId = searchParams.get("id");
  const sort = searchParams.get("sort") || FINDINGS_DEFAULT_SORT;
  const region = searchParams.get("filter[region__in]") || "";
  // Respect the user's muted preference from the URL; default to EXCLUDE
  // so the requirement view stays consistent with every other findings
  // surface in the app (findings page, resource drawer, overview widgets).
  const mutedFilter = searchParams.get("filter[muted]") || MUTED_FILTER.EXCLUDE;

  const checks = requirement.check_ids || [];

  const {
    findings,
    expandedFindings,
    isLoading,
    error,
    patchTriageUpdate,
    reload,
  } = useRequirementFindings({
    enabled:
      !disableFindings &&
      checks.length > 0 &&
      requirement.status !== "No findings",
    checkIds: checks,
    scanId,
    pageNumber,
    pageSize,
    sort,
    region,
    mutedFilter,
  });

  const handleTriageUpdate = async (input: UpdateFindingTriageInput) => {
    await updateFindingTriage(input);

    // Mutelist-shortcut statuses mute the finding server-side; refetch so the
    // list honors the muted filter, matching the resource drawer behavior.
    if (shouldRefreshAfterTriageUpdate(input)) {
      reload();
      return;
    }

    patchTriageUpdate(input);
  };

  const renderDetails = () => {
    if (!complianceId) {
      return null;
    }

    const mapper = getComplianceMapper(framework);
    const detailsComponent = mapper.getDetailsComponent(requirement);

    return <div className="w-full">{detailsComponent}</div>;
  };

  if (disableFindings) {
    return (
      <div className="w-full">
        {renderDetails()}
        <p className="mt-3 mb-1 text-sm font-medium text-gray-800 dark:text-gray-200">
          ⚠️ This requirement has no checks; therefore, there are no findings.
        </p>
      </div>
    );
  }

  const checksList = (
    <div className="flex items-center px-2 text-sm">
      <div className="w-full flex-col">
        <div className="mt-[-8px] mb-1 h-1 w-full border-b border-gray-200 dark:border-gray-800" />
        <span className="text-gray-600 dark:text-gray-200" aria-label="Checks">
          {checks.join(", ")}
        </span>
      </div>
    </div>
  );

  const accordionChecksItems = [
    {
      key: "checks",
      title: (
        <div className="flex items-center gap-2">
          <span className="text-button-primary">{checks.length}</span>
          {checks.length > 1 ? <span>Checks</span> : <span>Check</span>}
        </div>
      ),
      content: checksList,
    },
  ];

  const renderFindingsTable = () => {
    if (error) {
      return (
        <Alert variant="error" className="mt-3">
          <AlertTriangle />
          <AlertDescription className="flex flex-wrap items-center gap-2">
            <span>{error}</span>
            <Button
              variant="link"
              size="link-sm"
              className="h-auto p-0"
              onClick={reload}
            >
              Try again
            </Button>
          </AlertDescription>
        </Alert>
      );
    }

    if (isLoading && requirement.status !== "MANUAL") {
      return <SkeletonTableFindings />;
    }

    if (findings?.data?.length && findings.data.length > 0) {
      return (
        <>
          <h4 className="mb-2 text-sm font-medium">Findings</h4>

          <DataTable
            columns={getStandaloneFindingColumns({
              openFindingId,
              onTriageUpdateAction: handleTriageUpdate,
              onTriageNoteLoadAction: loadLatestFindingTriageNote,
            })}
            data={expandedFindings}
            metadata={findings?.meta}
            disableScroll={true}
          />
        </>
      );
    }

    return (
      <div className="mt-3 mb-1 text-sm font-medium text-gray-800 dark:text-gray-200">
        ⚠️ There are no findings for these regions
      </div>
    );
  };

  return (
    <div className="w-full">
      {requirement.invalid_config && (
        <Alert variant="warning" className="mb-3">
          <AlertTriangle />
          <AlertDescription>{INVALID_CONFIG_NOTE}</AlertDescription>
        </Alert>
      )}

      {renderDetails()}

      {checks.length > 0 && (
        <div className="my-4">
          <Accordion
            items={accordionChecksItems}
            variant="light"
            defaultExpandedKeys={[""]}
            className="dark:bg-bg-neutral-secondary rounded-lg bg-gray-50"
          />
        </div>
      )}

      {renderFindingsTable()}
    </div>
  );
};
