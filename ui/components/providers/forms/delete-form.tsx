"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import React, { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { deleteProvider } from "@/actions/providers";
import { DeleteIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { Form } from "@/components/ui/form";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

const formSchema = z.object({
  [ProviderCredentialFields.PROVIDER_ID]: z.string(),
});

export const DeleteForm = ({
  providerId,
  setIsOpen,
}: {
  providerId: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
  });
  const { toast } = useToast();
  const isLoading = form.formState.isSubmitting;

  async function onSubmitClient(formData: FormData) {
    // client-side validation
    const data = await deleteProvider(formData);

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
        description: "The provider was removed successfully.",
      });
    }
    setIsOpen(false); // Close the modal on success
  }

  return (
    <Form {...form}>
      <form action={onSubmitClient}>
        <input
          type="hidden"
          name={ProviderCredentialFields.PROVIDER_ID}
          value={providerId}
        />
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
            {isLoading ? "Loading" : "Delete"}
          </Button>
        </div>
      </form>
    </Form>
  );
};
