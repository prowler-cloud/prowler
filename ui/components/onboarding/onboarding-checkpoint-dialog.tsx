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
      // Overlay/Escape/X maps to "Finish here" — persists the handled marker once.
      onOpenChange={(next) => {
        if (!next) onFinish();
      }}
    >
      <DialogFooter>
        {/* Outline matches the app's modal secondary action (e.g. Launch Scan's Cancel). */}
        <Button variant="outline" onClick={onFinish}>
          Finish here
        </Button>
        <Button onClick={onContinue}>Continue the tour</Button>
      </DialogFooter>
    </Modal>
  );
}
