"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import React, { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { deleteUser } from "@/actions/users/users";
import { DeleteIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

const formSchema = z.object({
  userId: z.string(),
});

export const DeleteForm = ({
  userId,
  setIsOpen,
}: {
  userId: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      userId,
    },
  });
  const { toast } = useToast();
  const isLoading = form.formState.isSubmitting;

  async function onSubmitClient(values: z.infer<typeof formSchema>) {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );
    // client-side validation
    const data = await deleteUser(formData);

    if (data?.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const errorMessage = `${error.detail}`;
      // show error
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMessage,
      });
    } else {
      toast({
        title: "Success!",
        description: "The user was removed successfully.",
      });
    }
    setIsOpen(false); // Close the modal on success
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmitClient)}>
        <input type="hidden" name="id" value={userId} />
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
            ariaLabel="Delete"
            className="w-full"
            variant="solid"
            color="danger"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <DeleteIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Delete</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};