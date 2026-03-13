"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { sendInvite } from "@/actions/invitations/invitation";
import { Button } from "@/components/shadcn";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError } from "@/types";

const sendInvitationFormSchema = z.object({
  email: z.email({ error: "Please enter a valid email" }),
  roleId: z.string().min(1, "Role is required"),
});

export type FormValues = z.infer<typeof sendInvitationFormSchema>;

export const SendInvitationForm = ({
  roles = [],
  defaultRole = "admin",
  isSelectorDisabled = false,
}: {
  roles: Array<{ id: string; name: string }>;
  defaultRole?: string;
  isSelectorDisabled: boolean;
}) => {
  const { toast } = useToast();
  const router = useRouter();

  const form = useForm<FormValues>({
    resolver: zodResolver(sendInvitationFormSchema),
    defaultValues: {
      email: "",
      roleId: isSelectorDisabled ? defaultRole : "",
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    const formData = new FormData();
    formData.append("email", values.email);
    formData.append("role", values.roleId);

    try {
      const data = await sendInvite(formData);

      if (data?.errors && data.errors.length > 0) {
        data.errors.forEach((error: ApiError) => {
          const errorMessage = error.detail;
          const pointer = error.source?.pointer;
          switch (pointer) {
            case "/data/attributes/email":
              form.setError("email", {
                type: "server",
                message: errorMessage,
              });
              break;
            case "/data/relationships/roles":
              form.setError("roleId", {
                type: "server",
                message: errorMessage,
              });
              break;
            default:
              toast({
                variant: "destructive",
                title: "Oops! Something went wrong",
                description: errorMessage,
              });
          }
        });
      } else {
        const invitationId = data?.data?.id || "";
        router.push(`/invitations/check-details/?id=${invitationId}`);
      }
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "An unexpected error occurred. Please try again.",
      });
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col gap-4"
      >
        {/* Email Field */}
        <CustomInput
          control={form.control}
          name="email"
          type="email"
          label="Email"
          labelPlacement="inside"
          placeholder="Enter the email address"
          variant="flat"
          isRequired
        />

        <Controller
          name="roleId"
          control={form.control}
          render={({ field }) => (
            <div className="flex flex-col gap-1.5">
              <Select
                value={field.value || undefined}
                onValueChange={field.onChange}
                disabled={isSelectorDisabled}
              >
                <SelectTrigger aria-label="Select a role">
                  <SelectValue placeholder="Select a role" />
                </SelectTrigger>
                <SelectContent>
                  {isSelectorDisabled ? (
                    <SelectItem value={defaultRole}>{defaultRole}</SelectItem>
                  ) : (
                    roles.map((role) => (
                      <SelectItem key={role.id} value={role.id}>
                        {role.name}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
              {form.formState.errors.roleId && (
                <p className="text-text-error mt-2 text-sm">
                  {form.formState.errors.roleId.message}
                </p>
              )}
            </div>
          )}
        />

        {/* Submit Button */}
        <div className="flex w-full justify-end sm:gap-6">
          <Button
            type="submit"
            className="w-1/2"
            variant="default"
            size="lg"
            disabled={isLoading}
          >
            {isLoading ? (
              <>Loading</>
            ) : (
              <>
                <SaveIcon size={20} />
                <span>Send Invitation</span>
              </>
            )}
          </Button>
        </div>
      </form>
    </Form>
  );
};
