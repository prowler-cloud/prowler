"use client";

import { Ellipsis, VolumeX } from "lucide-react";
import { useState } from "react";
import { createPortal } from "react-dom";

import { JiraIcon } from "@/components/icons/services/IconServices";
import { Button } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown/action-dropdown";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { PROWLER_CLOUD_ONLY_TOOLTIP } from "@/lib/deployment";

import { MuteFindingsModal } from "./mute-findings-modal";

interface FloatingMuteButtonProps {
  selectedCount: number;
  selectedFindingIds: string[];
  onComplete?: () => void;
  /** Async resolver that returns actual finding UUIDs before opening modal */
  onBeforeOpen?: () => Promise<string[]>;
  /** When true, the toast warns that processing may take a few minutes */
  isBulkOperation?: boolean;
  /** Custom button label. Defaults to "Mute ({selectedCount})" */
  label?: string;
  /** Custom mute action label. Defaults to "Mute". */
  muteLabel?: string;
  /** Opens the Jira flow for the current selection. */
  onSendToJira?: () => void;
  /** Whether the Jira action is available for the current selection. */
  canSendToJira?: boolean;
  /** Whether the Jira action should be displayed in the action menu. */
  showSendToJira?: boolean;
  /** Custom Jira action label. Defaults to "Send to Jira". */
  sendToJiraLabel?: string;
  /** Tooltip shown when the Jira action is visible but disabled. */
  jiraDisabledTooltip?: string;
}

const CloudFeatureBadgeLink = () => (
  <Badge variant="cloud" asChild>
    <a
      href="https://prowler.com/pricing"
      target="_blank"
      rel="noopener noreferrer"
    >
      {PROWLER_CLOUD_ONLY_TOOLTIP}
    </a>
  </Badge>
);

export function FloatingMuteButton({
  selectedCount,
  selectedFindingIds,
  onComplete,
  onBeforeOpen,
  isBulkOperation = false,
  label,
  muteLabel = "Mute",
  onSendToJira,
  canSendToJira = false,
  showSendToJira = canSendToJira,
  sendToJiraLabel = "Send to Jira",
  jiraDisabledTooltip = PROWLER_CLOUD_ONLY_TOOLTIP,
}: FloatingMuteButtonProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [resolvedIds, setResolvedIds] = useState<string[]>([]);
  const [isResolving, setIsResolving] = useState(false);
  const [isPreparingMuteModal, setIsPreparingMuteModal] = useState(false);
  const [mutePreparationError, setMutePreparationError] = useState<
    string | null
  >(null);

  const handleModalOpenChange = (
    nextOpen: boolean | ((previousOpen: boolean) => boolean),
  ) => {
    const resolvedOpen =
      typeof nextOpen === "function" ? nextOpen(isModalOpen) : nextOpen;
    setIsModalOpen(resolvedOpen);

    if (!resolvedOpen) {
      setResolvedIds([]);
      setIsPreparingMuteModal(false);
      setMutePreparationError(null);
    }
  };

  const handleMuteClick = async () => {
    if (onBeforeOpen) {
      setResolvedIds([]);
      setMutePreparationError(null);
      setIsPreparingMuteModal(true);
      setIsModalOpen(true);
      setIsResolving(true);
      try {
        const ids = await onBeforeOpen();
        setResolvedIds(ids);
        setMutePreparationError(
          ids.length === 0
            ? "No findings could be resolved for this selection. Try refreshing the page and trying again."
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
      setIsModalOpen(true);
    }
  };

  const handleJiraClick = () => {
    if (!canSendToJira) return;

    onSendToJira?.();
  };

  const handleComplete = () => {
    setResolvedIds([]);
    onComplete?.();
  };

  const findingIds = onBeforeOpen ? resolvedIds : selectedFindingIds;

  return (
    <>
      <MuteFindingsModal
        isOpen={isModalOpen}
        onOpenChange={handleModalOpenChange}
        findingIds={findingIds}
        onComplete={handleComplete}
        isBulkOperation={isBulkOperation}
        isPreparing={isPreparingMuteModal}
        preparationError={mutePreparationError}
      />

      {/* Portaled to body: <main> is a layout container (container queries),
          which would otherwise capture this fixed button and scroll it away
          with the content. */}
      {typeof document !== "undefined"
        ? createPortal(
            <div className="animate-in fade-in slide-in-from-bottom-4 fixed right-6 bottom-6 z-50 flex gap-2 duration-300">
              <div className="shadow-lg">
                {showSendToJira ? (
                  <ActionDropdown
                    ariaLabel="Open selection actions"
                    trigger={
                      <Button disabled={isResolving} size="lg">
                        {isResolving ? (
                          <Spinner className="size-5" />
                        ) : (
                          <Ellipsis className="size-5" />
                        )}
                        {label ?? `${selectedCount} selected`}
                      </Button>
                    }
                  >
                    <ActionDropdownItem
                      icon={<VolumeX />}
                      label={muteLabel}
                      aria-label={muteLabel}
                      onSelect={() => void handleMuteClick()}
                    />
                    <ActionDropdownItem
                      icon={<JiraIcon size={20} />}
                      label={
                        <span className="flex items-center gap-2">
                          {sendToJiraLabel}
                          {!canSendToJira && <CloudFeatureBadgeLink />}
                        </span>
                      }
                      aria-label={sendToJiraLabel}
                      disabled={!canSendToJira}
                      disabledTooltip={jiraDisabledTooltip}
                      onSelect={handleJiraClick}
                    />
                  </ActionDropdown>
                ) : (
                  <Button
                    onClick={() => void handleMuteClick()}
                    disabled={isResolving}
                    size="lg"
                  >
                    {isResolving ? (
                      <Spinner className="size-5" />
                    ) : (
                      <VolumeX className="size-5" />
                    )}
                    Mute ({selectedCount})
                  </Button>
                )}
              </div>
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
