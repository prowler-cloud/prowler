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

interface OnboardingCheckpointDialogProps {
  open: boolean;
  // Start the guided sequence and continue into the next flow.
  onContinue: () => void;
  // End onboarding here. Closing via the overlay, Escape, or the X maps to this
  // same action (mirrors the welcome modal's dismiss convention).
  onFinish: () => void;
}

// Presentational checkpoint shown after the first provider is added. It owns no
// navigation, persistence, or sequence state: the watcher decides what to do on
// each choice so this component stays a pure render of the prompt.
export function OnboardingCheckpointDialog({
  open,
  onContinue,
  onFinish,
}: OnboardingCheckpointDialogProps) {
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        // Closing via the overlay, Escape, or the X is treated as "Finish here"
        // so the watcher persists the handled marker exactly once.
        if (!next) onFinish();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Provider added — keep exploring?</DialogTitle>
          <DialogDescription>
            Your first provider is added. Want a quick guided tour of scans,
            findings, compliance, and attack paths? You can stop anytime.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" onClick={onFinish}>
            Finish here
          </Button>
          <Button onClick={onContinue}>Continue the tour</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
