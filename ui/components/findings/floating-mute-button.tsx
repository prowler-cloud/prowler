"use client";

import { VolumeX } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn";
import { Spinner } from "@/components/shadcn/spinner/spinner";

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
}

export function FloatingMuteButton({
  selectedCount,
  selectedFindingIds,
  onComplete,
  onBeforeOpen,
  isBulkOperation = false,
  label,
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

  const handleClick = async () => {
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

      <div className="animate-in fade-in slide-in-from-bottom-4 fixed right-6 bottom-6 z-50 duration-300">
        <Button
          onClick={handleClick}
          disabled={isResolving}
          size="lg"
          className="shadow-lg"
        >
          {isResolving ? (
            <Spinner className="size-5" />
          ) : (
            <VolumeX className="size-5" />
          )}
          {label ?? `Mute (${selectedCount})`}
        </Button>
      </div>
    </>
  );
}
