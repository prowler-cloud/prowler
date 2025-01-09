"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Select, SelectItem } from "@nextui-org/react";
import { ShieldIcon, UserIcon } from "lucide-react";
import { Dispatch, SetStateAction } from "react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { updateUser, updateUserRole } from "@/actions/users/users";
import { SaveIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { editUserFormSchema } from "@/types";

export const EditForm = ({
  userId,
  userName,
  userEmail,
  userCompanyName,
  roles = [],
  currentRole = "",
  setIsOpen,
}: {
  userId: string;
  userName?: string;
  userEmail?: string;
  userCompanyName?: string;
  roles: Array<{ id: string; name: string }>;
  currentRole?: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const formSchema = editUserFormSchema();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      userId: userId,
      name: userName,
      email: userEmail,
      company_name: userCompanyName,
      role: roles.find((role) => role.name === currentRole)?.id || "",
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

    // Update basic user data
    if (values.name !== undefined) {
      formData.append("name", values.name);
    }
    if (values.email !== undefined) {
      formData.append("email", values.email);
    }
    if (values.company_name !== undefined) {
      formData.append("company_name", values.company_name);
    }

    // Always include userId
    formData.append("userId", userId);

    // Handle role updates separately
    if (values.role !== roles.find((role) => role.name === currentRole)?.id) {
      const roleFormData = new FormData();
      roleFormData.append("userId", userId);
      roleFormData.append("roleId", values.role || "");

      const roleUpdateResponse = await updateUserRole(roleFormData);

      if (roleUpdateResponse?.errors && roleUpdateResponse.errors.length > 0) {
        const error = roleUpdateResponse.errors[0];
        toast({
          variant: "destructive",
          title: "Role Update Failed",
          description: `${error.detail}`,
        });
        return;
      }
    }

    // Update other user attributes
    const data = await updateUser(formData);

    if (data?.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const errorMessage = `${error.detail}`;
      // Show error
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMessage,
      });
    } else {
      toast({
        title: "Success!",
        description: "The user was updated successfully.",
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
            <UserIcon className="mr-2 h-4 w-4" />
            <span className="text-gray-500">Name:</span>
            <span className="ml-2 font-semibold text-gray-900">{userName}</span>
          </div>
          <div className="flex items-center text-small text-gray-600">
            <ShieldIcon className="mr-2 h-4 w-4" />
            <span className="text-gray-500">Role:</span>
            <span className="ml-2 font-semibold text-gray-900">
              {currentRole}
            </span>
          </div>
        </div>
        <div className="flex flex-row gap-4">
          <div className="w-1/2">
            <CustomInput
              control={form.control}
              name="name"
              type="text"
              label="Name"
              labelPlacement="outside"
              placeholder={userName}
              variant="bordered"
              isRequired={false}
              isInvalid={!!form.formState.errors.name}
            />
          </div>
          <div className="w-1/2">
            <CustomInput
              control={form.control}
              name="company_name"
              type="text"
              label="Company Name"
              labelPlacement="outside"
              placeholder={userCompanyName}
              variant="bordered"
              isRequired={false}
              isInvalid={!!form.formState.errors.company_name}
            />
          </div>
        </div>

        <div>
          <CustomInput
            control={form.control}
            name="email"
            type="email"
            label="Email"
            labelPlacement="outside"
            placeholder={userEmail}
            variant="bordered"
            isRequired={false}
            isInvalid={!!form.formState.errors.email}
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
                labelPlacement="outside"
                placeholder="Select a role"
                classNames={{
                  selectorIcon: "right-2",
                }}
                variant="bordered"
                selectedKeys={[field.value || ""]}
                onSelectionChange={(selected) => {
                  const selectedKey = Array.from(selected).pop();
                  field.onChange(selectedKey || "");
                }}
              >
                {roles.map((role: { id: string; name: string }) => (
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
        <input type="hidden" name="userId" value={userId} />

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
