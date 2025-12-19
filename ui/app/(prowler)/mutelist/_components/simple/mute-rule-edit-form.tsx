"use client";

import { Input, Textarea } from "@heroui/input";
import { useActionState, useEffect } from "react";

import { updateMuteRule } from "@/actions/mute-rules";
import { MuteRuleActionState, MuteRuleData } from "@/actions/mute-rules/types";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";

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
  const { toast } = useToast();

  const [state, formAction, isPending] = useActionState<
    MuteRuleActionState,
    FormData
  >(updateMuteRule, null);

  useEffect(() => {
    if (state?.success) {
      toast({
        title: "Success",
        description: state.success,
      });
      onSuccess();
    } else if (state?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Error",
        description: state.errors.general,
      });
    }
  }, [state, toast, onSuccess]);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <input type="hidden" name="id" value={muteRule.id} />

      <Input
        name="name"
        label="Name"
        placeholder="Enter rule name"
        defaultValue={muteRule.attributes.name}
        isRequired
        variant="bordered"
        isInvalid={!!state?.errors?.name}
        errorMessage={state?.errors?.name}
        isDisabled={isPending}
      />

      <Textarea
        name="reason"
        label="Reason"
        placeholder="Enter the reason for muting these findings"
        defaultValue={muteRule.attributes.reason}
        isRequired
        variant="bordered"
        minRows={3}
        maxRows={6}
        isInvalid={!!state?.errors?.reason}
        errorMessage={state?.errors?.reason}
        isDisabled={isPending}
      />

      <div className="text-default-500 text-xs">
        <p>
          This rule is applied to{" "}
          {muteRule.attributes.finding_uids?.length || 0} findings.
        </p>
        <p className="mt-1">
          Note: You cannot modify the findings associated with this rule after
          creation.
        </p>
      </div>

      <FormButtons
        onCancel={onCancel}
        submitText="Update"
        isDisabled={isPending}
      />
    </form>
  );
}
