"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useRef, useState } from "react";

import { resolveFindingIdsByVisibleGroupResources } from "@/actions/findings/findings-by-resource";
import { CustomCheckboxMutedFindings } from "@/components/filters/custom-checkbox-muted-findings";
import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { OnboardingTrigger, PageReady } from "@/components/onboarding";
import { DataTable } from "@/components/shadcn/table";
import { isGroupedJiraDispatchEnabled } from "@/lib/deployment";
import { canDrillDownFindingGroup } from "@/lib/findings-groups";
import {
  createJiraBatchSelection,
  createJiraTargetSelection,
} from "@/lib/jira-dispatch-selection";
import { getFlowById } from "@/lib/onboarding";
import { createExploreFindingsTourStepHandlers } from "@/lib/tours/explore-findings.tour";
import { FindingGroupRow, MetaDataProps } from "@/types";
import { JIRA_DISPATCH_MODE, JIRA_DISPATCH_TARGET } from "@/types/integrations";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindingGroups } from "./column-finding-groups";
import { canMuteFindingGroup } from "./finding-group-selection";
import { FindingsSelectionContext } from "./findings-selection-context";
import {
  InlineResourceContainer,
  InlineResourceContainerHandle,
} from "./inline-resource-container";

const exploreFindingsFlow = getFlowById("explore-findings")!;
const EMPTY_FINDING_GROUPS: FindingGroupRow[] = [];

function buildSelectionSummary(
  groupCount: number,
  findingCount: number,
): string {
  return `${buildSelectionEntityLabel(groupCount, findingCount)} selected`;
}

function buildMuteActionLabel(
  groupCount: number,
  findingCount: number,
): string {
  return `Mute ${buildSelectionEntityLabel(groupCount, findingCount)}`;
}

function buildJiraActionLabel(
  groupCount: number,
  findingCount: number,
): string {
  return `Send ${buildSelectionEntityLabel(groupCount, findingCount)} to Jira`;
}

function buildSelectionEntityLabel(
  groupCount: number,
  findingCount: number,
): string {
  const parts = [
    buildEntityCountLabel(groupCount, "Group", "Groups"),
    buildEntityCountLabel(findingCount, "Finding", "Findings"),
  ].filter(Boolean);

  return parts.join(" and ");
}

function buildEntityCountLabel(
  count: number,
  singular: string,
  plural: string,
): string | null {
  if (count === 0) return null;

  return `${count} ${count === 1 ? singular : plural}`;
}

interface FindingsGroupTableProps {
  data: FindingGroupRow[];
  metadata?: MetaDataProps;
  resolvedFilters: Record<string, string>;
  hasHistoricalData: boolean;
  expandedCheckId?: string;
}

export function FindingsGroupTable({
  data,
  metadata,
  resolvedFilters,
  hasHistoricalData,
  expandedCheckId: requestedExpandedCheckId,
}: FindingsGroupTableProps) {
  const safeData = data ?? EMPTY_FINDING_GROUPS;
  const requestedGroup = requestedExpandedCheckId
    ? safeData.find((group) => group.checkId === requestedExpandedCheckId)
    : undefined;
  const initialExpandedCheckId =
    requestedGroup && canDrillDownFindingGroup(requestedGroup)
      ? requestedGroup.checkId
      : null;

  return (
    <FindingsGroupTableContent
      key={`${requestedExpandedCheckId ?? "manual"}:${initialExpandedCheckId ?? "collapsed"}`}
      data={safeData}
      metadata={metadata}
      resolvedFilters={resolvedFilters}
      hasHistoricalData={hasHistoricalData}
      initialExpandedCheckId={initialExpandedCheckId}
    />
  );
}

interface FindingsGroupTableContentProps {
  data: FindingGroupRow[];
  metadata?: MetaDataProps;
  resolvedFilters: Record<string, string>;
  hasHistoricalData: boolean;
  initialExpandedCheckId: string | null;
}

const FindingsGroupTableContent = ({
  data,
  metadata,
  resolvedFilters,
  hasHistoricalData,
  initialExpandedCheckId,
}: FindingsGroupTableContentProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [selectedExpandedCheckId, setSelectedExpandedCheckId] = useState<
    string | null
  >(initialExpandedCheckId);
  // Separate input (keystroke) from committed search (Enter) to avoid remounting InlineResourceContainer.
  const [resourceSearchInput, setResourceSearchInput] = useState("");
  const [resourceSearch, setResourceSearch] = useState("");
  const [resourceSelection, setResourceSelection] = useState<string[]>([]);
  const [isJiraModalOpen, setIsJiraModalOpen] = useState(false);
  const inlineRef = useRef<InlineResourceContainerHandle>(null);

  const safeData = data ?? EMPTY_FINDING_GROUPS;
  const expandedGroupCandidate = selectedExpandedCheckId
    ? safeData.find((group) => group.checkId === selectedExpandedCheckId)
    : undefined;
  const expandedGroup =
    expandedGroupCandidate && canDrillDownFindingGroup(expandedGroupCandidate)
      ? expandedGroupCandidate
      : null;
  const expandedCheckId = expandedGroup?.checkId ?? null;
  const activeResourceSelection = expandedCheckId ? resourceSelection : [];
  const hasResourceSelection = activeResourceSelection.length > 0;
  const filters = resolvedFilters;
  const groupedJiraDispatchEnabled = isGroupedJiraDispatchEnabled();

  // Exclude expanded group from group-level mutes when it has resource selections.
  const selectedCheckIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)]?.checkId)
    .filter(Boolean)
    .filter(
      (checkId) => !(hasResourceSelection && checkId === expandedCheckId),
    );

  const selectedFindings = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)])
    .filter(Boolean);

  const selectedGroupTitle =
    selectedFindings.length === 1 ? selectedFindings[0]?.checkTitle : undefined;
  const hasMixedJiraSelection =
    selectedCheckIds.length > 0 && hasResourceSelection;
  const jiraGroupSelectionTakesPrecedence = selectedCheckIds.length > 0;
  const jiraTargetIds = jiraGroupSelectionTakesPrecedence
    ? selectedCheckIds
    : activeResourceSelection;
  const jiraTargetType = jiraGroupSelectionTakesPrecedence
    ? JIRA_DISPATCH_TARGET.CHECK_ID
    : JIRA_DISPATCH_TARGET.FINDING_ID;
  const singleSelectedGroup =
    selectedCheckIds.length === 1
      ? selectedFindings.find(
          (finding) => finding.checkId === selectedCheckIds[0],
        )
      : undefined;
  const selectedJiraResourceCount = jiraGroupSelectionTakesPrecedence
    ? singleSelectedGroup
      ? singleSelectedGroup.resourcesFail
      : selectedCheckIds.length
    : activeResourceSelection.length;
  const jiraDispatchMode = jiraGroupSelectionTakesPrecedence
    ? JIRA_DISPATCH_MODE.GROUPED
    : activeResourceSelection.length > 1
      ? JIRA_DISPATCH_MODE.GROUPED
      : JIRA_DISPATCH_MODE.INDIVIDUAL;
  const canChooseGroupedJiraDispatch = jiraGroupSelectionTakesPrecedence
    ? !hasMixedJiraSelection &&
      selectedCheckIds.length === 1 &&
      selectedJiraResourceCount > 1
    : activeResourceSelection.length > 1;
  const jiraTitle = hasMixedJiraSelection
    ? undefined
    : jiraGroupSelectionTakesPrecedence
      ? selectedGroupTitle
      : expandedGroup?.checkTitle;
  const jiraSelection = hasMixedJiraSelection
    ? createJiraBatchSelection([
        {
          targetIds: selectedCheckIds,
          targetType: JIRA_DISPATCH_TARGET.CHECK_ID,
          dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
        },
        {
          targetIds: activeResourceSelection,
          targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
          ...(activeResourceSelection.length > 1
            ? {}
            : { dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL }),
        },
      ])
    : createJiraTargetSelection(jiraTargetIds, jiraTargetType);
  const jiraDescription = hasMixedJiraSelection
    ? `Create Jira issues for ${buildSelectionEntityLabel(
        selectedCheckIds.length,
        activeResourceSelection.length,
      )}.`
    : undefined;
  const hasJiraTargets = jiraTargetIds.length > 0;
  const isSingleFindingJiraDispatch =
    !jiraGroupSelectionTakesPrecedence && activeResourceSelection.length === 1;
  const canSendToJira =
    hasJiraTargets &&
    (isSingleFindingJiraDispatch || groupedJiraDispatchEnabled);
  const sendToJiraLabel = buildJiraActionLabel(
    selectedCheckIds.length,
    activeResourceSelection.length,
  );

  const selectableRowCount = safeData.filter((g) =>
    canMuteFindingGroup({
      resourcesFail: g.resourcesFail,
      resourcesTotal: g.resourcesTotal,
      muted: g.muted,
      mutedCount: g.mutedCount,
    }),
  ).length;

  const getRowCanSelect = (row: Row<FindingGroupRow>): boolean => {
    const group = row.original;
    return canMuteFindingGroup({
      resourcesFail: group.resourcesFail,
      resourcesTotal: group.resourcesTotal,
      muted: group.muted,
      mutedCount: group.mutedCount,
    });
  };

  const clearSelection = () => {
    setRowSelection({});
  };

  const isSelected = (id: string) => {
    return selectedCheckIds.includes(id);
  };

  const resolveGroupMuteIds = async (checkIds: string[]) => {
    const results = await Promise.all(
      checkIds.map((checkId) =>
        resolveFindingIdsByVisibleGroupResources({
          checkId,
          filters,
          hasDateOrScanFilter: hasHistoricalData,
          resourceSearch:
            checkId === expandedCheckId && resourceSearch
              ? resourceSearch
              : undefined,
        }),
      ),
    );

    return Array.from(new Set(results.flat()));
  };

  const resolveMuteIds = async (checkIds: string[]) =>
    resolveGroupMuteIds(checkIds);

  const handleMuteComplete = () => {
    clearSelection();
    setResourceSelection([]);
    inlineRef.current?.clearSelection();
    inlineRef.current?.refresh();
    router.refresh();
  };

  const handleDrillDown = (checkId: string, group: FindingGroupRow) => {
    if (!canDrillDownFindingGroup(group)) return;

    // Toggle: same group collapses, different group switches
    if (expandedCheckId === checkId) {
      handleCollapse();
      return;
    }
    setSelectedExpandedCheckId(checkId);
    setResourceSearchInput("");
    setResourceSearch("");
    setResourceSelection([]);
  };

  const handleCollapse = () => {
    setSelectedExpandedCheckId(null);
    setResourceSearchInput("");
    setResourceSearch("");
    setResourceSelection([]);
  };

  // Drives the onboarding "Open a finding group" step: opens the first row when
  // drillable, otherwise the first drillable group. Returns false when none can
  // open so the tour skips the resources step instead of hanging.
  const openFirstFindingGroup = (): boolean => {
    const target =
      safeData[0] && canDrillDownFindingGroup(safeData[0])
        ? safeData[0]
        : safeData.find((group) => canDrillDownFindingGroup(group));
    if (!target) return false;
    handleDrillDown(target.checkId, target);
    return true;
  };

  const columns = getColumnFindingGroups({
    rowSelection,
    selectableRowCount,
    onDrillDown: handleDrillDown,
    expandedCheckId,
    hasResourceSelection,
    filters,
  });

  const renderAfterRow = (row: Row<FindingGroupRow>) => {
    const group = row.original;
    if (group.checkId !== expandedCheckId || !expandedGroup) return null;

    return (
      <InlineResourceContainer
        ref={inlineRef}
        key={`${group.checkId}|${searchParams.toString()}|${resourceSearch}`}
        group={expandedGroup}
        resolvedFilters={resolvedFilters}
        hasHistoricalData={hasHistoricalData}
        resourceSearch={resourceSearch}
        columnCount={columns.length}
        onResourceSelectionChange={setResourceSelection}
      />
    );
  };

  return (
    <FindingsSelectionContext.Provider
      value={{
        selectedFindingIds: selectedCheckIds,
        selectedFindings,
        clearSelection,
        isSelected,
        resolveMuteIds,
      }}
    >
      {/* Gate the tour on having at least one finding group */}
      <div>
        <Suspense fallback={null}>
          {safeData.length > 0 && (
            <OnboardingTrigger
              flow={exploreFindingsFlow}
              stepHandlers={createExploreFindingsTourStepHandlers(
                openFirstFindingGroup,
              )}
            />
          )}
        </Suspense>
        {/* Signals the navbar that this route's data has loaded (enables the replay icon). */}
        <PageReady />
        <DataTable
          columns={columns}
          data={safeData}
          metadata={metadata}
          enableRowSelection
          rowSelection={rowSelection}
          onRowSelectionChange={setRowSelection}
          getRowCanSelect={getRowCanSelect}
          showSearch
          searchPlaceholder={
            expandedCheckId ? "Search resources..." : "Search by name"
          }
          controlledSearch={expandedCheckId ? resourceSearchInput : undefined}
          onSearchChange={expandedCheckId ? setResourceSearchInput : undefined}
          onSearchCommit={expandedCheckId ? setResourceSearch : undefined}
          searchBadge={
            expandedGroup
              ? { label: expandedGroup.checkTitle, onDismiss: handleCollapse }
              : undefined
          }
          toolbarRightContent={<CustomCheckboxMutedFindings />}
          renderAfterRow={renderAfterRow}
          // Anchor the "Open a finding group" tour step to the first group row
          // (there may be only one); driver.js resolves to the first match.
          getRowAttributes={(row) =>
            row.index === 0 ? { "data-tour-id": "explore-findings-group" } : {}
          }
        />
      </div>

      {(selectedCheckIds.length > 0 || hasResourceSelection) && (
        <FloatingMuteButton
          selectedCount={
            selectedCheckIds.length + activeResourceSelection.length
          }
          selectedFindingIds={[...selectedCheckIds, ...activeResourceSelection]}
          label={buildSelectionSummary(
            selectedCheckIds.length,
            activeResourceSelection.length,
          )}
          muteLabel={buildMuteActionLabel(
            selectedCheckIds.length,
            activeResourceSelection.length,
          )}
          onBeforeOpen={async () => {
            const [groupIds, resourceIds] = await Promise.all([
              selectedCheckIds.length > 0
                ? resolveGroupMuteIds(selectedCheckIds)
                : Promise.resolve([]),
              Promise.resolve(
                hasResourceSelection ? activeResourceSelection : [],
              ),
            ]);
            return [...groupIds, ...resourceIds];
          }}
          onComplete={handleMuteComplete}
          isBulkOperation={
            selectedCheckIds.length > 0 || activeResourceSelection.length > 1
          }
          showSendToJira={hasJiraTargets}
          canSendToJira={canSendToJira}
          sendToJiraLabel={sendToJiraLabel}
          onSendToJira={() => setIsJiraModalOpen(true)}
        />
      )}

      {canSendToJira && jiraSelection && (
        <SendToJiraModal
          isOpen={isJiraModalOpen}
          onOpenChange={setIsJiraModalOpen}
          findingTitle={jiraTitle}
          selection={jiraSelection}
          defaultDispatchMode={jiraDispatchMode}
          isFindingGroupSelection={
            !jiraGroupSelectionTakesPrecedence && Boolean(expandedGroup)
          }
          canChooseGroupedDispatch={canChooseGroupedJiraDispatch}
          selectedResourceCount={selectedJiraResourceCount}
          description={jiraDescription}
        />
      )}
    </FindingsSelectionContext.Provider>
  );
};
