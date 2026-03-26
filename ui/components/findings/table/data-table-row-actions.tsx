"use client";

import { Row } from "@tanstack/react-table";
import { VolumeOff, VolumeX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useContext, useState } from "react";

import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { JiraIcon } from "@/components/icons/services/IconServices";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Spinner } from "@/components/shadcn/spinner/spinner";

import { FindingsSelectionContext } from "./findings-selection-context";

export interface FindingRowData {
  id: string;
  attributes?: {
    muted?: boolean;
    check_metadata?: {
      checktitle?: string;
    };
  };
  // Flat shape for FindingGroupRow
  rowType?: string;
  checkId?: string;
  checkTitle?: string;
  mutedCount?: number;
  resourcesTotal?: number;
}

/**
 * Extract muted state and title from either FindingProps (nested attributes)
 * or FindingGroupRow (flat shape with rowType discriminant).
 */
function extractRowInfo(data: FindingRowData) {
  if (data.rowType === "group") {
    const allMuted =
      (data.mutedCount ?? 0) > 0 && data.mutedCount === data.resourcesTotal;
    return {
      isMuted: allMuted,
      title: data.checkTitle || "Security Finding",
    };
  }
  return {
    isMuted: data.attributes?.muted ?? false,
    title: data.attributes?.check_metadata?.checktitle || "Security Finding",
  };
}

interface DataTableRowActionsProps<T extends FindingRowData> {
  row: Row<T>;
  onMuteComplete?: (findingIds: string[]) => void;
}

export function DataTableRowActions<T extends FindingRowData>({
  row,
  onMuteComplete,
}: DataTableRowActionsProps<T>) {
  const router = useRouter();
  const finding = row.original;
  const [isJiraModalOpen, setIsJiraModalOpen] = useState(false);
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);

  const { isMuted, title: findingTitle } = extractRowInfo(finding);

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
  const muteKey = isGroup ? finding.checkId ?? finding.id : finding.id;

  // If current finding is selected and there are multiple selections, mute all
  // Otherwise, just mute this single finding
  const isCurrentSelected = selectedFindingIds.includes(muteKey);
  const hasMultipleSelected = selectedFindingIds.length > 1;

  const getDisplayIds = (): string[] => {
    if (isCurrentSelected && hasMultipleSelected) {
      return selectedFindingIds;
    }
    return [muteKey];
  };

  const getMuteLabel = () => {
    if (isMuted) return "Muted";
    const ids = getDisplayIds();
    if (ids.length > 1) {
      return `Mute ${ids.length} ${isGroup ? "Finding Groups" : "Findings"}`;
    }
    return isGroup ? "Mute Finding Group" : "Mute Finding";
  };

  const handleMuteClick = async () => {
    const displayIds = getDisplayIds();

    if (resolveMuteIds) {
      setIsResolving(true);
      const ids = await resolveMuteIds(displayIds);
      setResolvedIds(ids);
      setIsResolving(false);
      if (ids.length > 0) setIsMuteModalOpen(true);
    } else {
      // Regular findings — IDs are already valid finding UUIDs
      setResolvedIds(displayIds);
      setIsMuteModalOpen(true);
    }
  };

  const handleMuteComplete = () => {
    // Always clear selection when a finding is muted because:
    // rowSelection uses indices (0, 1, 2...) not IDs, so after refresh
    // the wrong findings would appear selected
    clearSelection();
    setResolvedIds([]);
    if (onMuteComplete) {
      onMuteComplete(getDisplayIds());
      return;
    }

    router.refresh();
  };

  return (
    <>
      {!isGroup && (
        <SendToJiraModal
          isOpen={isJiraModalOpen}
          onOpenChange={setIsJiraModalOpen}
          findingId={finding.id}
          findingTitle={findingTitle}
        />
      )}

      <MuteFindingsModal
        isOpen={isMuteModalOpen}
        onOpenChange={setIsMuteModalOpen}
        findingIds={resolvedIds}
        onComplete={handleMuteComplete}
        isBulkOperation={finding.rowType === "group"}
      />

      <div className="flex items-center justify-end">
        <ActionDropdown ariaLabel="Finding actions">
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
            disabled={isMuted || isResolving}
            onSelect={handleMuteClick}
          />
          {!isGroup && (
            <ActionDropdownItem
              icon={<JiraIcon size={20} />}
              label="Send to Jira"
              onSelect={() => setIsJiraModalOpen(true)}
            />
          )}
        </ActionDropdown>
      </div>
    </>
  );
}
