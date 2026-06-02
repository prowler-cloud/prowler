"use client";

import { Button } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";

interface OnboardingWelcomeModalProps {
  open: boolean;
  flowTitle?: string;
  flowDescription?: string;
  onAccept: () => void;
  onDismiss: () => void;
}

// Presentational entry point for the mandatory onboarding gate. It owns no
// navigation or persistence: accepting and dismissing are delegated to the
// caller (the gate) so this component stays reusable across any flow.
export function OnboardingWelcomeModal({
  open,
  flowTitle,
  flowDescription,
  onAccept,
  onDismiss,
}: OnboardingWelcomeModalProps) {
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        // Closing via the overlay, Escape, or the X is treated as a dismiss so
        // the gate can persist the dismissal record exactly once.
        if (!next) onDismiss();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{flowTitle}</DialogTitle>
          {/* Always render a description region: Radix associates the dialog
              with it via aria-describedby, and flows supply copy here. */}
          <DialogDescription>{flowDescription}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" onClick={onDismiss}>
            Skip for now
          </Button>
          <Button onClick={onAccept}>Get started</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
