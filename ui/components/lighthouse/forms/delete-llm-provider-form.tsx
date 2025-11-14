"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import React, { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { deleteLighthouseProviderByType } from "@/actions/lighthouse/lighthouse";
import { DeleteIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import type { LighthouseProvider } from "@/types/lighthouse";

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
      router.push("/lighthouse/config");
    }
  }

  return (
    <Form {...form}>
      <form action={onSubmitClient}>
        <input type="hidden" name="providerType" value={providerType} />
        <div className="flex w-full justify-center sm:gap-6">
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
