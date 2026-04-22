"use client";

import { Dispatch, SetStateAction, useState, useTransition } from "react";

import { createMuteRule } from "@/actions/mute-rules";
import { MuteRuleActionState } from "@/actions/mute-rules/types";
import { Button, Input, Textarea } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";
import { Label } from "@/components/ui/form/Label";
import {
  enforceMuteRuleReasonLimit,
  getMuteRuleReasonCounterText,
} from "@/lib/mute-rules";

interface MuteFindingsModalProps {
  isOpen: boolean;
  onOpenChange: Dispatch<SetStateAction<boolean>>;
  findingIds: string[];
  onComplete?: () => void;
  isBulkOperation?: boolean;
  isPreparing?: boolean;
  preparationError?: string | null;
}

export function MuteFindingsModal({
  isOpen,
  onOpenChange,
  findingIds,
  onComplete,
  isBulkOperation = false,
  isPreparing = false,
  preparationError = null,
}: MuteFindingsModalProps) {
  const { toast } = useToast();
  const [state, setState] = useState<MuteRuleActionState | null>(null);
  const [reason, setReason] = useState("");
  const [reasonLengthError, setReasonLengthError] = useState<string>();
  const [isPending, startTransition] = useTransition();

  const handleCancel = () => {
    onOpenChange(false);
  };

  const isSubmitDisabled =
    isPending ||
    isPreparing ||
    findingIds.length === 0 ||
    Boolean(preparationError);
  const nameError = state?.errors?.name;
  const reasonError = reasonLengthError || state?.errors?.reason;

  const handleReasonChange = (
    event: React.ChangeEvent<HTMLTextAreaElement>,
  ) => {
    const nextReason = enforceMuteRuleReasonLimit(event.target.value);

    setReason(nextReason.value);
    setReasonLengthError(nextReason.error);
  };

  return (
    <Modal
      open={isOpen}
      onOpenChange={onOpenChange}
      title="Mute Findings"
      description="Create a mute rule for the selected findings."
      size="lg"
    >
      <form
        className="flex flex-col gap-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (isSubmitDisabled) {
            return;
          }

          const formData = new FormData(e.currentTarget);
          formData.set("reason", reason);

          const nextReason = enforceMuteRuleReasonLimit(reason);
          if (nextReason.error) {
            setReasonLengthError(nextReason.error);
            return;
          }

          startTransition(() => {
            void (async () => {
              const result = await createMuteRule(null, formData);
              if (!result) return;

              if (result.success) {
                toast({
                  title: "Success",
                  description: isBulkOperation
                    ? "Mute rule created. It may take a few minutes for all findings to update."
                    : result.success,
                });
                onComplete?.();
                onOpenChange(false);
              } else if (result.errors?.general) {
                toast({
                  variant: "destructive",
                  title: "Error",
                  description: result.errors.general,
                });
              }
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

        {isPreparing ? (
          <>
            <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-xl border p-4">
              <p className="text-text-neutral-primary text-sm font-medium">
                Preparing mute rule
              </p>
              <p className="text-text-neutral-tertiary mt-1 text-xs">
                Large finding groups can take a few seconds while we gather the
                matching findings for this rule.
              </p>
            </div>

            <div className="space-y-4" aria-hidden="true">
              <div className="border-border-neutral-secondary bg-bg-neutral-tertiary space-y-3 rounded-xl border p-4">
                <Skeleton className="h-3 w-24 rounded" />
                <Skeleton className="h-5 w-36 rounded" />
                <Skeleton className="h-4 w-56 rounded" />
              </div>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Skeleton className="h-3 w-20 rounded" />
                  <Skeleton className="h-11 w-full rounded-lg" />
                  <Skeleton className="h-3 w-44 rounded" />
                </div>
                <div className="space-y-2">
                  <Skeleton className="h-3 w-20 rounded" />
                  <Skeleton className="h-28 w-full rounded-lg" />
                  <Skeleton className="h-3 w-36 rounded" />
                </div>
              </div>
            </div>

            <div className="flex w-full justify-end gap-4">
              <Button
                type="button"
                variant="ghost"
                size="lg"
                onClick={handleCancel}
              >
                Cancel
              </Button>
              <Button type="button" size="lg" disabled>
                Preparing...
              </Button>
            </div>
          </>
        ) : preparationError ? (
          <>
            <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-xl border p-4">
              <p className="text-text-neutral-primary text-sm font-medium">
                We couldn&apos;t prepare this mute action.
              </p>
              <p className="text-text-neutral-secondary mt-1 text-xs">
                {preparationError}
              </p>
            </div>

            <div className="flex w-full justify-end">
              <Button
                type="button"
                variant="ghost"
                size="lg"
                onClick={handleCancel}
              >
                Close
              </Button>
            </div>
          </>
        ) : (
          <>
            <div className="space-y-4">
              <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-xl border p-4">
                <p className="text-text-neutral-tertiary text-xs font-medium tracking-[0.08em] uppercase">
                  Selected findings
                </p>
                <p className="text-text-neutral-secondary mt-2 text-sm">
                  You are about to mute{" "}
                  <span className="text-text-neutral-primary font-semibold">
                    {findingIds.length}
                  </span>{" "}
                  {findingIds.length === 1 ? "finding" : "findings"}.
                </p>
                <p className="text-text-neutral-tertiary mt-1 text-xs">
                  Muted findings remain hidden by default and can still be
                  reviewed by enabling muted filters.
                </p>
              </div>

              <div className="space-y-4">
                <div>
                  <p className="text-text-neutral-tertiary text-xs font-medium tracking-[0.08em] uppercase">
                    Rule details
                  </p>
                </div>

                <div className="space-y-2">
                  <Label
                    className="text-text-neutral-secondary text-xs font-light tracking-tight"
                    htmlFor="mute-rule-name"
                  >
                    Rule Name
                  </Label>
                  <Input
                    id="mute-rule-name"
                    name="name"
                    placeholder="e.g., Ignore dev environment S3 buckets"
                    required
                    disabled={isPending}
                    aria-invalid={nameError ? "true" : "false"}
                    aria-describedby={
                      nameError
                        ? "mute-rule-name-error"
                        : "mute-rule-name-description"
                    }
                  />
                  <p
                    id="mute-rule-name-description"
                    className="text-text-neutral-tertiary text-xs"
                  >
                    A descriptive name for this mute rule
                  </p>
                  {nameError ? (
                    <p
                      id="mute-rule-name-error"
                      className="text-text-error-primary text-xs"
                    >
                      {nameError}
                    </p>
                  ) : null}
                </div>

                <div className="space-y-2">
                  <Label
                    className="text-text-neutral-secondary text-xs font-light tracking-tight"
                    htmlFor="mute-rule-reason"
                  >
                    Reason
                  </Label>
                  <Textarea
                    id="mute-rule-reason"
                    name="reason"
                    placeholder="e.g., These are expected findings in the development environment"
                    required
                    disabled={isPending}
                    value={reason}
                    onChange={handleReasonChange}
                    rows={4}
                    maxLength={500}
                    aria-invalid={reasonError ? "true" : "false"}
                    aria-describedby={
                      reasonError
                        ? "mute-rule-reason-error"
                        : "mute-rule-reason-description"
                    }
                  />
                  <div className="flex items-center justify-between gap-3">
                    <p
                      id="mute-rule-reason-description"
                      className="text-text-neutral-tertiary text-xs"
                    >
                      Explain why these findings are being muted
                    </p>
                    <p className="text-text-neutral-tertiary shrink-0 text-xs">
                      {getMuteRuleReasonCounterText(reason)}
                    </p>
                  </div>
                  {reasonError ? (
                    <p
                      id="mute-rule-reason-error"
                      className="text-text-error-primary text-xs"
                    >
                      {reasonError}
                    </p>
                  ) : null}
                </div>
              </div>
            </div>

            <FormButtons
              setIsOpen={onOpenChange}
              onCancel={handleCancel}
              submitText="Mute Findings"
              isDisabled={isPending}
            />
          </>
        )}
      </form>
    </Modal>
  );
}
