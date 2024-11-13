"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { sendInvite } from "@/actions/invitations/invitation";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError } from "@/types";

const sendInvitationFormSchema = z.object({
  email: z.string().email("Please enter a valid email"),
});

export type FormValues = z.infer<typeof sendInvitationFormSchema>;

export const SendInvitationForm = () => {
  const { toast } = useToast();
  const router = useRouter();

  const form = useForm<FormValues>({
    resolver: zodResolver(sendInvitationFormSchema),
    defaultValues: {
      email: "",
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    const formData = new FormData();
    formData.append("email", values.email);

    try {
      const data = await sendInvite(formData);

      if (data?.errors && data.errors.length > 0) {
        data.errors.forEach((error: ApiError) => {
          const errorMessage = error.detail;
          switch (error.source.pointer) {
            case "/data/attributes/email":
              form.setError("email", {
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
    } catch (error) {
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
        className="flex flex-col space-y-4"
      >
        <CustomInput
          control={form.control}
          name="email"
          type="email"
          label="Email"
          labelPlacement="inside"
          placeholder="Enter the email address"
          variant="bordered"
          isRequired
          isInvalid={!!form.formState.errors.email}
        />

        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="submit"
            ariaLabel="Send Invitation"
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Send Invitation</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
