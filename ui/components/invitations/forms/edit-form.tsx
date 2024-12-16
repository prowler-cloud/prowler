import { zodResolver } from "@hookform/resolvers/zod";
import { Select, SelectItem } from "@nextui-org/react";
import { MailIcon, ShieldIcon } from "lucide-react";
import { Dispatch, SetStateAction } from "react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { updateInvite } from "@/actions/invitations/invitation";
import { SaveIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { editInviteFormSchema } from "@/types";

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
        className="flex flex-col space-y-4"
      >
        <div className="flex flex-row justify-center space-x-4 rounded-lg bg-gray-50 p-3">
          <div className="flex items-center text-small text-gray-600">
            <MailIcon className="mr-2 h-4 w-4" />
            <span className="text-gray-500">Email:</span>
            <span className="ml-2 font-semibold text-gray-900">
              {invitationEmail}
            </span>
          </div>
          <div className="flex items-center text-small text-gray-600">
            <ShieldIcon className="mr-2 h-4 w-4" />
            <span className="text-gray-500">Role:</span>
            <span className="ml-2 font-semibold text-gray-900">
              {currentRole}
            </span>
          </div>
        </div>

        <div>
          <CustomInput
            control={form.control}
            name="invitationEmail"
            type="email"
            label="Email"
            labelPlacement="outside"
            placeholder={invitationEmail}
            variant="bordered"
            isRequired={false}
            isInvalid={!!form.formState.errors.invitationEmail}
          />
        </div>
        <div>
          <Controller
            name="role"
            control={form.control}
            render={({ field }) => (
              <Select
                {...field}
                label="Role"
                placeholder="Select a role"
                variant="bordered"
                selectedKeys={[field.value || ""]}
                onSelectionChange={(selected) =>
                  field.onChange(selected?.currentKey || "")
                }
              >
                {roles.map((role) => (
                  <SelectItem key={role.id}>{role.name}</SelectItem>
                ))}
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

        <div className="flex w-full justify-center sm:space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-full bg-transparent"
            variant="faded"
            size="lg"
            radius="lg"
            onPress={() => setIsOpen(false)}
            isDisabled={isLoading}
          >
            <span>Cancel</span>
          </CustomButton>

          <CustomButton
            type="submit"
            ariaLabel="Save"
            className="w-full"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Save</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
