"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { revertRealtimeAction } from "@/app/(prowler)/realtime/_actions";
import { ConfirmModal } from "@/app/(prowler)/realtime/_components/shared/confirm-modal";
import {
  DEMO_TOOLTIP,
  NO_PERMISSION_TOOLTIP,
} from "@/app/(prowler)/realtime/_lib/demo";
import type { RealtimeAction } from "@/app/(prowler)/realtime/_types";
import {
  Button,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  useToast,
} from "@/components/shadcn";

interface RevertActionButtonProps {
  action: RealtimeAction;
  canWrite: boolean;
  demo: boolean;
}

/** Undo an automatic fix after a confirmation that says what changes back. */
export function RevertActionButton({
  action,
  canWrite,
  demo,
}: RevertActionButtonProps) {
  const router = useRouter();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);

  const revert = async () => {
    setPending(true);
    const result = await revertRealtimeAction(action.id);
    setPending(false);
    setOpen(false);
    if (!result.ok) {
      toast({
        variant: "destructive",
        title: "The fix was not reverted",
        description: result.error,
      });
      return;
    }
    toast({
      title: "Fix reverted",
      description: `${action.resource_uid} is back as it was before the fix.`,
    });
    router.refresh();
  };

  if (!canWrite) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          {/* Disabled buttons get no pointer events: the span takes the hover and focus. */}
          <span tabIndex={0} className="inline-flex">
            <Button variant="outline" size="sm" disabled>
              Revert
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {demo ? DEMO_TOOLTIP : NO_PERMISSION_TOOLTIP}
        </TooltipContent>
      </Tooltip>
    );
  }

  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        Revert
      </Button>
      <ConfirmModal
        open={open}
        onOpenChange={(next) => !pending && setOpen(next)}
        title="Revert this fix?"
        description={`Prowler will change ${action.resource_uid} back to how it was before the fix, using the undo it recorded. The issue the fix closed will be open again.`}
        confirmLabel={pending ? "Reverting…" : "Revert"}
        cancelLabel="Keep the fix"
        destructive
        pending={pending}
        onConfirm={revert}
      >
        {action.summary && (
          <p className="text-text-neutral-secondary text-sm">
            Fix: {action.summary}
          </p>
        )}
      </ConfirmModal>
    </>
  );
}
