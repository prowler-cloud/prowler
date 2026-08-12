"use client";

import { Row } from "@tanstack/react-table";
import { VolumeOff, VolumeX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useContext, useState } from "react";

import { JiraDispatchActionItem } from "@/components/findings/jira-dispatch-action-item";
import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { isFindingGroupMuted } from "@/lib/findings-groups";
import { buildJiraActionLabel } from "@/lib/jira-dispatch-action";
import { createJiraDispatchPayload } from "@/lib/jira-dispatch-selection";
import { buildFindingResourceContext } from "@/lib/lighthouse/context/contributions";
import { isCloud } from "@/lib/shared/env";
import { getOptionalText } from "@/lib/utils";
import type {
  FindingTriageContext,
  FindingTriageDetailLoadHandler,
  FindingTriageNoteLoadHandler,
  FindingTriageSummary,
  FindingTriageUpdateHandler,
} from "@/types/findings-triage";
import { JIRA_DISPATCH_TARGET } from "@/types/integrations";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";
import type { ProviderType } from "@/types/providers";

import { canMuteFindingGroup } from "./finding-group-selection";
import { FindingNoteActionItem } from "./finding-triage-cells";
import { FindingsSelectionContext } from "./findings-selection-context";
import {
  LighthouseSkillsSubmenu,
  useLighthousePromptLaunch,
  useLighthouseSkillLaunch,
} from "./lighthouse-skills-launch";

export interface FindingRowData {
  id: string;
  attributes?: {
    muted?: boolean;
    check_metadata?: {
      checktitle?: string;
    };
  };
  severity?: string;
  status?: string;
  triage?: FindingTriageSummary;
  relationships?: {
    resource?: {
      attributes?: {
        name?: string;
      };
    };
    provider?: {
      attributes?: {
        alias?: string;
        provider?: string;
      };
    };
  };
  // Flat shape for FindingGroupRow
  rowType?: string;
  checkId?: string;
  checkTitle?: string;
  muted?: boolean;
  mutedCount?: number;
  resourcesFail?: number;
  resourcesTotal?: number;
}

/**
 * Extract muted state and title from either FindingProps (nested attributes)
 * or FindingGroupRow (flat shape with rowType discriminant).
 */
function extractRowInfo(data: FindingRowData) {
  if (data.rowType === "group") {
    const isMuted = isFindingGroupMuted({
      muted: data.muted,
      mutedCount: data.mutedCount ?? 0,
      resourcesFail: data.resourcesFail ?? 0,
      resourcesTotal: data.resourcesTotal ?? 0,
    });

    return {
      isMuted,
      canMute: canMuteFindingGroup({
        resourcesFail: data.resourcesFail ?? 0,
        resourcesTotal: data.resourcesTotal ?? 0,
        muted: data.muted,
        mutedCount: data.mutedCount ?? 0,
      }),
      title: data.checkTitle || "Security Finding",
    };
  }
  return {
    isMuted: data.attributes?.muted ?? false,
    canMute: !(data.attributes?.muted ?? false),
    title: data.attributes?.check_metadata?.checktitle || "Security Finding",
  };
}

interface DataTableRowActionsProps<T extends FindingRowData> {
  row: Row<T>;
  onMuteComplete?: (findingIds: string[]) => void;
  findingContext?: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: FindingTriageNoteLoadHandler;
  onTriageDetailLoadAction?: FindingTriageDetailLoadHandler;
}

export function DataTableRowActions<T extends FindingRowData>({
  row,
  onMuteComplete,
  findingContext,
  onTriageUpdateAction,
  onTriageNoteLoadAction,
  onTriageDetailLoadAction,
}: DataTableRowActionsProps<T>) {
  const router = useRouter();
  const finding = row.original;
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);
  const [isPreparingMuteModal, setIsPreparingMuteModal] = useState(false);
  const [mutePreparationError, setMutePreparationError] = useState<
    string | null
  >(null);

  const { isMuted, canMute, title: findingTitle } = extractRowInfo(finding);
  const resolvedFindingContext = findingContext ?? {
    title: findingTitle,
    resource: getOptionalText(
      finding.relationships?.resource?.attributes?.name,
    ),
    provider: getOptionalText(
      finding.relationships?.provider?.attributes?.alias,
    ),
    providerType: getOptionalText(
      finding.relationships?.provider?.attributes?.provider,
    ) as ProviderType | undefined,
  };

  // Get selection context - if there are other selected rows, include them
  const selectionContext = useContext(FindingsSelectionContext);
  const { selectedFindingIds, clearSelection, resolveMuteIds } =
    selectionContext || {
      selectedFindingIds: [],
      clearSelection: () => {},
    };

  const [resolvedIds, setResolvedIds] = useState<string[]>([]);
  const [isResolving, setIsResolving] = useState(false);

  // For group rows, use checkId (for the resolve API); for regular findings, use id (UUID).
  const isGroup = finding.rowType === "group";
  const muteKey = isGroup ? (finding.checkId ?? finding.id) : finding.id;

  // If current finding is selected and there are multiple selections, mute all
  // Otherwise, just mute this single finding
  const isCurrentSelected = selectedFindingIds.includes(muteKey);
  const hasMultipleSelected = selectedFindingIds.length > 1;

  const actionTargetIds =
    isCurrentSelected && hasMultipleSelected ? selectedFindingIds : [muteKey];

  const getMuteLabel = () => {
    if (isMuted) return "Muted";
    if (actionTargetIds.length > 1) {
      return `Mute ${actionTargetIds.length} ${isGroup ? "Finding Groups" : "Findings"}`;
    }
    return isGroup ? "Mute Finding Group" : "Mute Finding";
  };

  const jiraTargetType = isGroup
    ? JIRA_DISPATCH_TARGET.CHECK_ID
    : JIRA_DISPATCH_TARGET.FINDING_ID;
  const selectedJiraResourceCount = isGroup
    ? (finding.resourcesFail ?? 0)
    : undefined;
  const jiraPayload = createJiraDispatchPayload({
    targetIds: actionTargetIds,
    targetType: jiraTargetType,
    findingTitle,
    selectedResourceCount: selectedJiraResourceCount,
  });
  const jiraLabel = buildJiraActionLabel({
    findingGroupCount: isGroup ? actionTargetIds.length : 0,
    findingCount: isGroup ? 0 : actionTargetIds.length,
  });

  const handleMuteModalOpenChange = (
    nextOpen: boolean | ((previousOpen: boolean) => boolean),
  ) => {
    const resolvedOpen =
      typeof nextOpen === "function" ? nextOpen(isMuteModalOpen) : nextOpen;
    setIsMuteModalOpen(resolvedOpen);

    if (!resolvedOpen) {
      setIsPreparingMuteModal(false);
      setMutePreparationError(null);
      setResolvedIds([]);
    }
  };

  const handleMuteClick = async () => {
    if (resolveMuteIds) {
      setResolvedIds([]);
      setMutePreparationError(null);
      setIsPreparingMuteModal(true);
      setIsMuteModalOpen(true);
      setIsResolving(true);
      try {
        const ids = await resolveMuteIds(actionTargetIds);
        setResolvedIds(ids);
        setMutePreparationError(
          ids.length === 0
            ? "No findings could be resolved for this group. Try refreshing the page and trying again."
            : null,
        );
      } catch {
        setMutePreparationError(
          "We couldn't prepare this mute action. Please try again.",
        );
      } finally {
        setIsPreparingMuteModal(false);
        setIsResolving(false);
      }
    } else {
      // Regular findings — IDs are already valid finding UUIDs
      setResolvedIds(actionTargetIds);
      setIsMuteModalOpen(true);
    }
  };

  const handleMuteComplete = () => {
    // Muted findings may leave the filtered dataset after refresh.
    clearSelection();
    setResolvedIds([]);
    if (onMuteComplete) {
      onMuteComplete(actionTargetIds);
      return;
    }

    router.refresh();
  };

  const launchSkill = useLighthouseSkillLaunch();
  const launchPrompt = useLighthousePromptLaunch();
  // Skills are finding-level only: group rows carry check ids, not finding
  // UUIDs, so their menu never offers the Lighthouse entries (see below).
  const buildSkillFindingItem = () =>
    buildFindingResourceContext({ findingId: finding.id });
  const handleLaunchSkill = (skill: LighthouseSkillDefinition) => {
    launchSkill(skill, buildSkillFindingItem());
  };
  const handleSubmitPrompt = (text: string) => {
    launchPrompt(text, buildSkillFindingItem());
  };

  return (
    <>
      <MuteFindingsModal
        isOpen={isMuteModalOpen}
        onOpenChange={handleMuteModalOpenChange}
        findingIds={resolvedIds}
        onComplete={handleMuteComplete}
        isBulkOperation={finding.rowType === "group"}
        isPreparing={isPreparingMuteModal}
        preparationError={mutePreparationError}
      />

      <div
        className="flex items-center justify-end"
        onClick={(event) => event.stopPropagation()}
      >
        <ActionDropdown ariaLabel="Finding actions">
          {!isGroup && (
            <FindingNoteActionItem
              triage={finding.triage}
              findingContext={resolvedFindingContext}
              onTriageUpdateAction={onTriageUpdateAction}
              onTriageNoteLoadAction={onTriageNoteLoadAction}
              onTriageDetailLoadAction={onTriageDetailLoadAction}
            />
          )}
          <ActionDropdownItem
            icon={
              isMuted ? (
                <VolumeOff className="size-5" />
              ) : isResolving ? (
                <Spinner className="size-5" />
              ) : (
                <VolumeX className="size-5" />
              )
            }
            label={isResolving ? "Resolving..." : getMuteLabel()}
            disabled={!canMute || isResolving}
            onSelect={handleMuteClick}
          />
          <JiraDispatchActionItem label={jiraLabel} payload={jiraPayload} />
          {isCloud() && !isGroup && (
            <LighthouseSkillsSubmenu
              onLaunch={handleLaunchSkill}
              onSubmitPrompt={handleSubmitPrompt}
            />
          )}
        </ActionDropdown>
      </div>
    </>
  );
}
