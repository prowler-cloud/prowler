"use client";

import { Button } from "@/components/shadcn";
import { DialogFooter } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal/modal";

interface OnboardingCheckpointDialogProps {
  open: boolean;
  onContinue: () => void;
  onFinish: () => void;
}

export function OnboardingCheckpointDialog({
  open,
  onContinue,
  onFinish,
}: OnboardingCheckpointDialogProps) {
  return (
    <Modal
      open={open}
      title="Provider added — keep exploring?"
      description="Your first provider is added. Want a quick guided tour of scans, findings, compliance, and attack paths? You can stop anytime."
      size="lg"
      // Overlay / Escape / X close maps to "Finish here" so the watcher persists
      // the handled marker exactly once.
      onOpenChange={(next) => {
        if (!next) onFinish();
      }}
    >
      <DialogFooter>
        <Button variant="ghost" onClick={onFinish}>
          Finish here
        </Button>
        <Button onClick={onContinue}>Continue the tour</Button>
      </DialogFooter>
    </Modal>
  );
}
