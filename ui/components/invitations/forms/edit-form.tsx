"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
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
  setIsOpen,
}: {
  invitationId: string;
  invitationEmail?: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const formSchema = editInviteFormSchema;

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      invitationId,
      invitationEmail: invitationEmail,
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();
    console.log(values);

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await updateInvite(formData);

    if (data?.error) {
      const errorMessage = `${data.error}`;
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMessage,
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
        <div className="text-md">
          Current email: <span className="font-bold">{invitationEmail}</span>
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
