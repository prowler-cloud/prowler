import { zodResolver } from "@hookform/resolvers/zod";
import { MailIcon, ShieldIcon } from "lucide-react";
import { Dispatch, SetStateAction } from "react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { updateInvite } from "@/actions/invitations/invitation";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form, FormButtons } from "@/components/ui/form";
import { editInviteFormSchema } from "@/types";

import { Card, CardContent } from "../../shadcn";

export const EditForm = ({
  invitationId,
  invitationEmail,
  roles = [],
  currentRole = "",
  setIsOpen,
}: {
  invitationId: string;
  invitationEmail?: string;
  roles: Array<{ id: string; name: string }>;
  currentRole?: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const formSchema = editInviteFormSchema;

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      invitationId,
      invitationEmail: invitationEmail || "",
      role: roles.find((role) => role.name === currentRole)?.id || "",
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const changedFields: { [key: string]: any } = {};

    // Check if the email changed
    if (values.invitationEmail && values.invitationEmail !== invitationEmail) {
      changedFields.invitationEmail = values.invitationEmail;
    }

    // Check if the role changed
    const currentRoleId =
      roles.find((role) => role.name === currentRole)?.id || "";
    if (values.role && values.role !== currentRoleId) {
      changedFields.role = values.role;
    }

    // If there are no changes, avoid the request
    if (Object.keys(changedFields).length === 0) {
      toast({
        title: "No changes detected",
        description: "Please modify at least one field before saving.",
      });
      return;
    }

    changedFields.invitationId = invitationId; // Always include the ID

    const formData = new FormData();
    Object.entries(changedFields).forEach(([key, value]) => {
      formData.append(key, value);
    });

    const data = await updateInvite(formData);

    if (data?.error) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: `${data.error}`,
      });
    } else {
      toast({
        title: "Success!",
        description: "The invitation was updated successfully.",
      });
      setIsOpen(false); // Close the modal on success
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col gap-4"
      >
        <Card variant="inner">
          <CardContent className="flex flex-row justify-center gap-4">
            <div className="text-small text-text-neutral-secondary flex items-center">
              <MailIcon className="text-text-neutral-secondary mr-2 h-4 w-4" />
              <span className="text-text-neutral-secondary">Email:</span>
              <span className="text-text-neutral-secondary ml-2 font-semibold">
                {invitationEmail}
              </span>
            </div>
            <div className="text-small flex items-center text-gray-600">
              <ShieldIcon className="text-text-neutral-secondary mr-2 h-4 w-4" />
              <span className="text-text-neutral-secondary">Role:</span>
              <span className="text-text-neutral-secondary ml-2 font-semibold">
                {currentRole}
              </span>
            </div>
          </CardContent>
        </Card>

        <div>
          <CustomInput
            control={form.control}
            name="invitationEmail"
            type="email"
            label="Email"
            labelPlacement="outside"
            placeholder={invitationEmail}
            variant="flat"
            isRequired={false}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="text-text-neutral-secondary text-sm font-medium">
            Role
          </label>
          <Controller
            name="role"
            control={form.control}
            render={({ field }) => (
              <Select value={field.value} onValueChange={field.onChange}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a role" />
                </SelectTrigger>
                <SelectContent>
                  {roles.map((role) => (
                    <SelectItem key={role.id} value={role.id}>
                      {role.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          />

          {form.formState.errors.role && (
            <p className="mt-2 text-sm text-red-600">
              {form.formState.errors.role.message}
            </p>
          )}
        </div>
        <input type="hidden" name="invitationId" value={invitationId} />

        <FormButtons setIsOpen={setIsOpen} isDisabled={isLoading} />
      </form>
    </Form>
  );
};
