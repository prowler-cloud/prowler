"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import React, { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { revokeInvite } from "@/actions/invitations/invitation";
import { DeleteIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { Form } from "@/components/ui/form";

const formSchema = z.object({
  invitationId: z.string(),
});

export const DeleteForm = ({
  invitationId,
  setIsOpen,
}: {
  invitationId: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      invitationId,
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
    const data = await revokeInvite(formData);

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
        description: "The invitation was revoked successfully.",
      });
    }
    setIsOpen(false); // Close the modal on success
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmitClient)}>
        <input type="hidden" name="id" value={invitationId} />
        <div className="flex w-full justify-end gap-4">
          <Button
            type="button"
            variant="ghost"
            size="lg"
            onClick={() => setIsOpen(false)}
            disabled={isLoading}
          >
            Cancel
          </Button>

          <Button
            type="submit"
            variant="destructive"
            size="lg"
            disabled={isLoading}
          >
            {!isLoading && <DeleteIcon size={24} />}
            {isLoading ? "Loading" : "Revoke"}
          </Button>
        </div>
      </form>
    </Form>
  );
};
