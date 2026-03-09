"use client";

import { VolumeX } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn";

import { MuteFindingsModal } from "./mute-findings-modal";

interface FloatingMuteButtonProps {
  selectedCount: number;
  selectedFindingIds: string[];
  onComplete?: () => void;
}

export function FloatingMuteButton({
  selectedCount,
  selectedFindingIds,
  onComplete,
}: FloatingMuteButtonProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);

  return (
    <>
      <MuteFindingsModal
        isOpen={isModalOpen}
        onOpenChange={setIsModalOpen}
        findingIds={selectedFindingIds}
        onComplete={onComplete}
      />

      <div className="animate-in fade-in slide-in-from-bottom-4 fixed right-6 bottom-6 z-50 duration-300">
        <Button
          onClick={() => setIsModalOpen(true)}
          size="lg"
          className="shadow-lg"
        >
          <VolumeX className="size-5" />
          Mute ({selectedCount})
        </Button>
      </div>
    </>
  );
}
