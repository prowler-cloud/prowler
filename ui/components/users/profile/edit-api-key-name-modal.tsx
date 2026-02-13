"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { updateApiKey } from "@/actions/api-keys/api-keys";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form, FormButtons } from "@/components/ui/form";

import { EnrichedApiKey } from "./api-keys/types";
import { isApiKeyNameDuplicate } from "./api-keys/utils";

interface EditApiKeyNameModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: EnrichedApiKey | null;
  onSuccess: () => void;
  existingApiKeys: EnrichedApiKey[];
}

const editApiKeyNameSchema = z.object({
  name: z.string().min(1, "Name is required"),
});

type FormValues = z.infer<typeof editApiKeyNameSchema>;

export const EditApiKeyNameModal = ({
  isOpen,
  onClose,
  apiKey,
  onSuccess,
  existingApiKeys,
}: EditApiKeyNameModalProps) => {
  const { toast } = useToast();

  const form = useForm<FormValues>({
    resolver: zodResolver(editApiKeyNameSchema),
    defaultValues: {
      name: apiKey?.attributes.name || "",
    },
  });

  // Sync form data when apiKey changes or modal opens
  useEffect(() => {
    if (isOpen && apiKey) {
      form.reset({ name: apiKey.attributes.name || "" });
    }
  }, [isOpen, apiKey, form]);

  const onSubmitClient = async (values: FormValues) => {
    try {
      if (!apiKey) {
        throw new Error("API key not found");
      }

      if (isApiKeyNameDuplicate(values.name, existingApiKeys, apiKey.id)) {
        throw new Error(
          "An API key with this name already exists. Please choose a different name.",
        );
      }

      const result = await updateApiKey(apiKey.id, {
        name: values.name.trim(),
      });

      if (result.error) {
        throw new Error(result.error);
      }

      form.reset();
      onSuccess();
      onClose();
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description:
          error instanceof Error
            ? error.message
            : "An unexpected error occurred",
      });
    }
  };

  const handleClose = () => {
    form.reset();
    onClose();
  };

  return (
    <Modal
      open={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Edit API Key Name"
      size="lg"
    >
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmitClient)}
          className="flex flex-col gap-4"
        >
          <div className="text-sm text-slate-400">
            Prefix: {apiKey?.attributes.prefix}
          </div>

          <div className="flex flex-col gap-2">
            <CustomInput
              control={form.control}
              name="name"
              type="text"
              label="Name"
              labelPlacement="outside"
              placeholder="My API Key"
              variant="bordered"
              isRequired
            />
          </div>

          <FormButtons
            onCancel={handleClose}
            submitText="Save Changes"
            cancelText="Cancel"
            loadingText="Processing..."
            isDisabled={!form.formState.isValid}
          />
        </form>
      </Form>
    </Modal>
  );
};
