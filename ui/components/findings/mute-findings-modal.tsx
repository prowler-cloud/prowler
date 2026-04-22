"use client";

import { Dispatch, SetStateAction, useState, useTransition } from "react";

import { createMuteRule } from "@/actions/mute-rules";
import { MuteRuleActionState } from "@/actions/mute-rules/types";
import { Button, Input, Textarea } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";

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
  const reasonError = state?.errors?.reason;

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
          if (isSubmitDisabled) {
            return;
          }

          const formData = new FormData(e.currentTarget);

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
            <div className="rounded-lg bg-slate-50 p-4 dark:bg-slate-800/50">
              <div className="flex items-start gap-3">
                <Spinner className="mt-0.5 size-5 shrink-0" />
                <div className="space-y-1">
                  <p className="text-sm font-medium text-slate-900 dark:text-white">
                    Preparing findings to mute...
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Large finding groups can take a few seconds while we gather
                    the matching findings.
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-3" aria-hidden="true">
              <div className="space-y-2">
                <Skeleton className="h-4 w-24 rounded" />
                <Skeleton className="h-11 w-full rounded-lg" />
                <Skeleton className="h-3 w-40 rounded" />
              </div>
              <div className="space-y-2">
                <Skeleton className="h-4 w-20 rounded" />
                <Skeleton className="h-24 w-full rounded-lg" />
                <Skeleton className="h-3 w-44 rounded" />
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
                <Spinner className="size-4" />
                Preparing...
              </Button>
            </div>
          </>
        ) : preparationError ? (
          <>
            <div className="rounded-lg bg-slate-50 p-4 dark:bg-slate-800/50">
              <p className="text-sm font-medium text-slate-900 dark:text-white">
                We couldn&apos;t prepare this mute action.
              </p>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
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

            <div className="space-y-2">
              <label
                className="text-sm font-medium text-slate-900 dark:text-white"
                htmlFor="mute-rule-name"
              >
                Rule Name
              </label>
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
                className="text-xs text-slate-500 dark:text-slate-400"
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
              <label
                className="text-sm font-medium text-slate-900 dark:text-white"
                htmlFor="mute-rule-reason"
              >
                Reason
              </label>
              <Textarea
                id="mute-rule-reason"
                name="reason"
                placeholder="e.g., These are expected findings in the development environment"
                required
                disabled={isPending}
                rows={4}
                aria-invalid={reasonError ? "true" : "false"}
                aria-describedby={
                  reasonError
                    ? "mute-rule-reason-error"
                    : "mute-rule-reason-description"
                }
              />
              <p
                id="mute-rule-reason-description"
                className="text-xs text-slate-500 dark:text-slate-400"
              >
                Explain why these findings are being muted
              </p>
              {reasonError ? (
                <p
                  id="mute-rule-reason-error"
                  className="text-text-error-primary text-xs"
                >
                  {reasonError}
                </p>
              ) : null}
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
