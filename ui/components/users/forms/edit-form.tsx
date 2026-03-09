"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ShieldIcon, UserIcon } from "lucide-react";
import { Dispatch, SetStateAction } from "react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { updateUser, updateUserRole } from "@/actions/users/users";
import { Card } from "@/components/shadcn";
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
        className="flex flex-col gap-4"
      >
        <Card
          variant="inner"
          className="flex flex-row items-center justify-center gap-4"
        >
          <div className="text-small flex items-center">
            <UserIcon className="mr-2 h-4 w-4" />
            <span className="text-text-neutral-secondary">Name:</span>
            <span className="ml-2 font-semibold">{userName}</span>
          </div>
          <div className="text-small flex items-center">
            <ShieldIcon className="mr-2 h-4 w-4" />
            <span className="text-text-neutral-secondary">Role:</span>
            <span className="ml-2 font-semibold">
              {currentRole ? currentRole : "No role"}
            </span>
          </div>
        </Card>
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
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <Controller
            name="role"
            control={form.control}
            render={({ field }) => (
              <Select value={field.value} onValueChange={field.onChange}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a role" />
                </SelectTrigger>
                <SelectContent>
                  {roles.map((role: { id: string; name: string }) => (
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
        <input type="hidden" name="userId" value={userId} />

        <FormButtons setIsOpen={setIsOpen} isDisabled={isLoading} />
      </form>
    </Form>
  );
};
