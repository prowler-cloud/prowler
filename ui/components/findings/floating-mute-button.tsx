"use client";

import { VolumeX } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn";
import { TreeSpinner } from "@/components/shadcn/tree-view/tree-spinner";

import { MuteFindingsModal } from "./mute-findings-modal";

interface FloatingMuteButtonProps {
  selectedCount: number;
  selectedFindingIds: string[];
  onComplete?: () => void;
  /** Async resolver that returns actual finding UUIDs before opening modal */
  onBeforeOpen?: () => Promise<string[]>;
}

export function FloatingMuteButton({
  selectedCount,
  selectedFindingIds,
  onComplete,
  onBeforeOpen,
}: FloatingMuteButtonProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [resolvedIds, setResolvedIds] = useState<string[]>([]);
  const [isResolving, setIsResolving] = useState(false);

  const handleClick = async () => {
    if (onBeforeOpen) {
      setIsResolving(true);
      const ids = await onBeforeOpen();
      setResolvedIds(ids);
      setIsResolving(false);
      if (ids.length > 0) {
        setIsModalOpen(true);
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
        onOpenChange={setIsModalOpen}
        findingIds={findingIds}
        onComplete={handleComplete}
      />

      <div className="animate-in fade-in slide-in-from-bottom-4 fixed right-6 bottom-6 z-50 duration-300">
        <Button
          onClick={handleClick}
          disabled={isResolving}
          size="lg"
          className="shadow-lg"
        >
          {isResolving ? (
            <TreeSpinner className="size-5" />
          ) : (
            <VolumeX className="size-5" />
          )}
          Mute ({selectedCount})
        </Button>
      </div>
    </>
  );
}
