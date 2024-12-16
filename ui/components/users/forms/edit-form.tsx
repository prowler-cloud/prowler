"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { updateUser } from "@/actions/users/users";
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
  setIsOpen,
}: {
  userId: string;
  userName?: string;
  userEmail?: string;
  userCompanyName?: string;
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
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

    // Check if the value is not undefined before appending to FormData
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
        <div className="text-md">
          Current name: <span className="font-bold">{userName}</span>
        </div>
        <div>
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
