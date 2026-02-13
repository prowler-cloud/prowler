"use client";

import { Input, Textarea } from "@heroui/input";
import {
  Dispatch,
  SetStateAction,
  useEffect,
  useRef,
  useState,
  useTransition,
} from "react";

import { createMuteRule } from "@/actions/mute-rules";
import { MuteRuleActionState } from "@/actions/mute-rules/types";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";

interface MuteFindingsModalProps {
  isOpen: boolean;
  onOpenChange: Dispatch<SetStateAction<boolean>>;
  findingIds: string[];
  onComplete?: () => void;
}

export function MuteFindingsModal({
  isOpen,
  onOpenChange,
  findingIds,
  onComplete,
}: MuteFindingsModalProps) {
  const { toast } = useToast();
  const [state, setState] = useState<MuteRuleActionState | null>(null);
  const [isPending, startTransition] = useTransition();

  // Use refs to avoid stale closures in useEffect
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  const onOpenChangeRef = useRef(onOpenChange);
  onOpenChangeRef.current = onOpenChange;

  useEffect(() => {
    if (state?.success) {
      toast({
        title: "Success",
        description: state.success,
      });
      onCompleteRef.current?.();
      onOpenChangeRef.current(false);
    } else if (state?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Error",
        description: state.errors.general,
      });
    }
  }, [state, toast]);

  const handleCancel = () => {
    onOpenChange(false);
  };

  return (
    <Modal
      open={isOpen}
      onOpenChange={onOpenChange}
      title="Mute Findings"
      size="lg"
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          const formData = new FormData(e.currentTarget);

          startTransition(() => {
            void (async () => {
              const result = await createMuteRule(null, formData);
              setState(result);
            })();
          });
        }}
      >
        <input
          type="hidden"
          name="finding_ids"
          value={JSON.stringify(findingIds)}
        />

        <div className="rounded-lg bg-slate-50 p-3 dark:bg-slate-800/50">
          <p className="text-sm text-slate-600 dark:text-slate-400">
            You are about to mute{" "}
            <span className="font-semibold text-slate-900 dark:text-white">
              {findingIds.length}
            </span>{" "}
            {findingIds.length === 1 ? "finding" : "findings"}.
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">
            Muted findings will be hidden by default but can be shown using
            filters.
          </p>
        </div>

        <Input
          name="name"
          label="Rule Name"
          placeholder="e.g., Ignore dev environment S3 buckets"
          isRequired
          variant="bordered"
          isInvalid={!!state?.errors?.name}
          errorMessage={state?.errors?.name}
          isDisabled={isPending}
          description="A descriptive name for this mute rule"
        />

        <Textarea
          name="reason"
          label="Reason"
          placeholder="e.g., These are expected findings in the development environment"
          isRequired
          variant="bordered"
          minRows={3}
          maxRows={6}
          isInvalid={!!state?.errors?.reason}
          errorMessage={state?.errors?.reason}
          isDisabled={isPending}
          description="Explain why these findings are being muted"
        />

        <FormButtons
          setIsOpen={onOpenChange}
          onCancel={handleCancel}
          submitText="Mute Findings"
          isDisabled={isPending}
        />
      </form>
    </Modal>
  );
}
