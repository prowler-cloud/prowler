"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import React, { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { deleteLighthouseProviderByType } from "@/actions/lighthouse-v1/lighthouse";
import { DeleteIcon } from "@/components/icons";
import { useToast } from "@/components/shadcn";
import { Form, FormButtons } from "@/components/shadcn/form";
import type { LighthouseProvider } from "@/types/lighthouse-v1";

const formSchema = z.object({
  providerType: z.string(),
});

export const DeleteLLMProviderForm = ({
  providerType,
  setIsOpen,
}: {
  providerType: LighthouseProvider;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const router = useRouter();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
  });
  const { toast } = useToast();
  const isLoading = form.formState.isSubmitting;

  async function onSubmitClient(formData: FormData) {
    const providerType = formData.get("providerType") as LighthouseProvider;
    const data = await deleteLighthouseProviderByType(providerType);

    if (data?.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const errorMessage = `${error.detail}`;
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMessage,
      });
    } else {
      toast({
        title: "Success!",
        description: "The LLM provider was removed successfully.",
      });

      setIsOpen(false);
      router.push("/lighthouse/settings");
    }
  }

  return (
    <Form {...form}>
      <form action={onSubmitClient}>
        <input
          type="hidden"
          name="providerType"
          value={providerType}
          aria-label="Provider Type"
        />
        <FormButtons
          setIsOpen={setIsOpen}
          submitText="Delete"
          submitColor="danger"
          rightIcon={<DeleteIcon size={24} />}
          isDisabled={isLoading}
        />
      </form>
    </Form>
  );
};
