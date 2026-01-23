"use client";

import { Row } from "@tanstack/react-table";
import { VolumeOff, VolumeX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useContext, useState } from "react";

import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { VerticalDotsIcon } from "@/components/icons";
import { JiraIcon } from "@/components/icons/services/IconServices";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/shadcn/dropdown/dropdown";
import type { FindingProps } from "@/types/components";

import { FindingsSelectionContext } from "./findings-selection-context";

interface DataTableRowActionsProps {
  row: Row<FindingProps>;
}

export function DataTableRowActions({ row }: DataTableRowActionsProps) {
  const router = useRouter();
  const finding = row.original;
  const [isJiraModalOpen, setIsJiraModalOpen] = useState(false);
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);

  const isMuted = finding.attributes.muted;

  // Get selection context - if there are other selected rows, include them
  const selectionContext = useContext(FindingsSelectionContext);
  const { selectedFindingIds, clearSelection } = selectionContext || {
    selectedFindingIds: [],
    clearSelection: () => {},
  };

  const findingTitle =
    finding.attributes.check_metadata?.checktitle || "Security Finding";

  // If current finding is selected and there are multiple selections, mute all
  // Otherwise, just mute this single finding
  const isCurrentSelected = selectedFindingIds.includes(finding.id);
  const hasMultipleSelected = selectedFindingIds.length > 1;

  const getMuteIds = (): string[] => {
    if (isCurrentSelected && hasMultipleSelected) {
      // Mute all selected including current
      return selectedFindingIds;
    }
    // Just mute the current finding
    return [finding.id];
  };

  const getMuteDescription = (): string => {
    if (isMuted) {
      return "This finding is already muted";
    }
    const ids = getMuteIds();
    if (ids.length > 1) {
      return `Mute ${ids.length} selected findings`;
    }
    return "Mute this finding";
  };

  const handleMuteComplete = () => {
    // Always clear selection when a finding is muted because:
    // 1. If the muted finding was selected, its index now points to a different finding
    // 2. rowSelection uses indices (0, 1, 2...) not IDs, so after refresh the wrong findings would appear selected
    clearSelection();
    router.refresh();
  };

  return (
    <>
      <SendToJiraModal
        isOpen={isJiraModalOpen}
        onOpenChange={setIsJiraModalOpen}
        findingId={finding.id}
        findingTitle={findingTitle}
      />

      <MuteFindingsModal
        isOpen={isMuteModalOpen}
        onOpenChange={setIsMuteModalOpen}
        findingIds={getMuteIds()}
        onComplete={handleMuteComplete}
      />

      <div className="flex items-center justify-end">
        <DropdownMenu modal={false}>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              aria-label="Finding actions"
              className="hover:bg-bg-neutral-tertiary rounded-md p-1 transition-colors"
            >
              <VerticalDotsIcon
                size={20}
                className="text-text-neutral-secondary"
              />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            className="border-border-neutral-secondary bg-bg-neutral-secondary w-56"
          >
            <DropdownMenuLabel>Actions</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              disabled={isMuted}
              onSelect={() => setIsMuteModalOpen(true)}
              className="flex cursor-pointer items-center gap-2"
            >
              {isMuted ? (
                <VolumeOff className="text-muted-foreground size-5 shrink-0" />
              ) : (
                <VolumeX className="text-muted-foreground size-5 shrink-0" />
              )}
              <div className="flex flex-col">
                <span>
                  {isMuted ? "Muted" : "Mute"}
                  {!isMuted && isCurrentSelected && hasMultipleSelected && (
                    <span className="ml-1 text-xs text-slate-500">
                      ({selectedFindingIds.length})
                    </span>
                  )}
                </span>
                <span className="text-muted-foreground text-xs">
                  {getMuteDescription()}
                </span>
              </div>
            </DropdownMenuItem>
            <DropdownMenuItem
              onSelect={() => setIsJiraModalOpen(true)}
              className="flex cursor-pointer items-center gap-2"
            >
              <JiraIcon size={20} className="text-muted-foreground shrink-0" />
              <div className="flex flex-col">
                <span>Send to Jira</span>
                <span className="text-muted-foreground text-xs">
                  Create a Jira issue for this finding
                </span>
              </div>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </>
  );
}
