"use client";

import { Button } from "@/components/shadcn";
import { DialogFooter } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal/modal";

interface OnboardingWelcomeModalProps {
  open: boolean;
  flowTitle?: string;
  flowDescription?: string;
  onAccept: () => void;
  onDismiss: () => void;
}

export function OnboardingWelcomeModal({
  open,
  flowTitle,
  flowDescription,
  onAccept,
  onDismiss,
}: OnboardingWelcomeModalProps) {
  return (
    <Modal
      open={open}
      title={flowTitle}
      description={flowDescription}
      size="lg"
      // Overlay/Escape/X counts as dismiss — gate persists the record once.
      onOpenChange={(next) => {
        if (!next) onDismiss();
      }}
    >
      <DialogFooter>
        <Button variant="ghost" onClick={onDismiss}>
          Skip for now
        </Button>
        <Button onClick={onAccept}>Get started</Button>
      </DialogFooter>
    </Modal>
  );
}
