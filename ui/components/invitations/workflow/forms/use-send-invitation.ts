"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useFormState, type UseFormProps } from "react-hook-form";
import * as z from "zod";

import { sendInvite } from "@/actions/invitations/invitation";
import { toSentInvitation } from "@/actions/invitations/invitation.adapter";
import { useToast } from "@/components/shadcn";
import { ApiError } from "@/types";
import type { SentInvitation } from "@/types/onboarding-invite";

export const sendInvitationFormSchema = z.object({
  email: z.email({ error: "Please enter a valid email" }),
  roleId: z.string().min(1, "Role is required"),
});

export type SendInvitationFormValues = z.infer<typeof sendInvitationFormSchema>;

const EMAIL_ERROR_POINTER = "/data/attributes/email";
const ROLES_ERROR_POINTER = "/data/relationships/roles";

interface UseSendInvitationOptions {
  // Where the invitation is sent from, forwarded to the API as `?source=`
  // so the origin can be told apart (e.g. the onboarding invite step).
  source?: string;
  defaultRoleId?: string;
  // `onChange` lets a caller gate its submit button on `isValid`.
  mode?: UseFormProps<SendInvitationFormValues>["mode"];
  onSuccess: (invitation: SentInvitation) => void;
}

/** Owns an invitation form: schema, submit, API error mapping and toasts. */
export function useSendInvitation({
  source,
  defaultRoleId = "",
  mode = "onSubmit",
  onSuccess,
}: UseSendInvitationOptions) {
  const { toast } = useToast();
  const form = useForm<SendInvitationFormValues>({
    resolver: zodResolver(sendInvitationFormSchema),
    mode,
    defaultValues: { email: "", roleId: defaultRoleId },
  });
  // A hook, not `form.formState` read inline: the React Compiler keys its memo
  // on the stable `form` object and would freeze a proxy read.
  const { isSubmitting, isValid } = useFormState({ control: form.control });

  const onSubmit = form.handleSubmit(async (values) => {
    const formData = new FormData();
    formData.append("email", values.email);
    formData.append("role", values.roleId);
    if (source) formData.append("source", source);

    try {
      const data = await sendInvite(formData);

      if (data?.errors && data.errors.length > 0) {
        data.errors.forEach((error: ApiError) => {
          const message = error.detail;
          switch (error.source?.pointer) {
            case EMAIL_ERROR_POINTER:
              form.setError("email", { type: "server", message });
              break;
            case ROLES_ERROR_POINTER:
              form.setError("roleId", { type: "server", message });
              break;
            default:
              toast({
                variant: "destructive",
                title: "Oops! Something went wrong",
                description: message,
              });
          }
        });
        return;
      }

      const invitation = toSentInvitation(data);
      if (!invitation) {
        // A transport failure returns nothing and a rejection can come back
        // as a bare `error` without an `errors` array; neither created an
        // invitation, so neither is a success.
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description:
            typeof data?.error === "string"
              ? data.error
              : "The invitation could not be sent. Please try again.",
        });
        return;
      }
      onSuccess(invitation);
    } catch {
      toast({
        variant: "destructive",
        title: "Error",
        description: "An unexpected error occurred. Please try again.",
      });
    }
  });

  return { form, onSubmit, isSubmitting, isValid };
}
