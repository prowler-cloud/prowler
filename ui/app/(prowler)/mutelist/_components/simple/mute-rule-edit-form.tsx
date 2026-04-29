"use client";

import { FormEvent, useState } from "react";

import { updateMuteRule } from "@/actions/mute-rules";
import { MuteRuleActionState, MuteRuleData } from "@/actions/mute-rules/types";
import { Input, Textarea } from "@/components/shadcn";
import { FormButtons } from "@/components/ui/form";
import { Label } from "@/components/ui/form/Label";
import { useMuteRuleAction } from "@/hooks/use-mute-rule-action";
import {
  enforceMuteRuleReasonLimit,
  getMuteRuleReasonCounterText,
} from "@/lib/mute-rules";

interface MuteRuleEditFormProps {
  muteRule: MuteRuleData;
  onSuccess: () => void;
  onCancel: () => void;
}

export function MuteRuleEditForm({
  muteRule,
  onSuccess,
  onCancel,
}: MuteRuleEditFormProps) {
  const [state, setState] = useState<MuteRuleActionState>(null);
  const [reason, setReason] = useState(muteRule.attributes.reason);
  const [reasonLengthError, setReasonLengthError] = useState<string>();
  const { isPending, runAction } = useMuteRuleAction();

  const handleReasonChange = (value: string) => {
    const nextReason = enforceMuteRuleReasonLimit(value);

    setReason(nextReason.value);
    setReasonLengthError(nextReason.error);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);
    formData.set("reason", reason);

    const nextReason = enforceMuteRuleReasonLimit(reason);
    if (nextReason.error) {
      setReasonLengthError(nextReason.error);
      return;
    }

    runAction(() => updateMuteRule(null, formData), {
      setState,
      onSuccess,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-5">
      <input type="hidden" name="id" value={muteRule.id} />

      <div className="space-y-4">
        <div className="space-y-4">
          <div className="space-y-2">
            <Label
              className="text-text-neutral-secondary text-xs font-light tracking-tight"
              htmlFor="mute-rule-name"
            >
              Name
            </Label>
            <Input
              id="mute-rule-name"
              name="name"
              placeholder="Enter rule name"
              defaultValue={muteRule.attributes.name}
              required
              disabled={isPending}
              aria-invalid={state?.errors?.name ? "true" : "false"}
              aria-describedby={
                state?.errors?.name
                  ? "mute-rule-name-error"
                  : "mute-rule-name-description"
              }
            />
            <p
              id="mute-rule-name-description"
              className="text-text-neutral-tertiary text-xs"
            >
              A short label that helps identify this mute rule in the table
            </p>
            {state?.errors?.name ? (
              <p
                id="mute-rule-name-error"
                className="text-text-error-primary text-xs"
              >
                {state.errors.name}
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
              placeholder="Enter the reason for muting these findings"
              value={reason}
              onChange={(event) => handleReasonChange(event.target.value)}
              required
              rows={4}
              maxLength={500}
              disabled={isPending}
              aria-invalid={
                reasonLengthError || state?.errors?.reason ? "true" : "false"
              }
              aria-describedby={
                reasonLengthError || state?.errors?.reason
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
            {reasonLengthError || state?.errors?.reason ? (
              <p
                id="mute-rule-reason-error"
                className="text-text-error-primary text-xs"
              >
                {reasonLengthError || state?.errors?.reason}
              </p>
            ) : null}
          </div>
        </div>

        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-xl border p-4">
          <p className="text-text-neutral-tertiary text-xs font-medium tracking-[0.08em] uppercase">
            Muted findings
          </p>
          <p className="text-text-neutral-secondary mt-2 text-sm">
            This rule is currently applied to{" "}
            <span className="text-text-neutral-primary font-medium">
              {muteRule.attributes.finding_uids?.length || 0}
            </span>{" "}
            findings.
          </p>
          <p className="text-text-neutral-tertiary mt-1 text-xs">
            The associated findings stay fixed after creation and can&apos;t be
            changed from this dialog.
          </p>
        </div>
      </div>

      <FormButtons
        onCancel={onCancel}
        submitText="Update"
        isDisabled={isPending}
      />
    </form>
  );
}
