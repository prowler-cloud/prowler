"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { createApiKey } from "@/actions/api-keys/api-keys";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";
import { Form, FormButtons } from "@/components/ui/form";

import { DEFAULT_EXPIRY_DAYS } from "./api-keys/constants";
import { calculateExpiryDate } from "./api-keys/utils";

interface CreateApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (apiKey: string) => void;
}

const createApiKeySchema = z.object({
  name: z.string().min(1, "Name is required"),
  expiresInDays: z.string().refine((val) => {
    const num = parseInt(val);
    return num >= 1 && num <= 3650;
  }, "Must be between 1 and 3650 days"),
});

type FormValues = z.infer<typeof createApiKeySchema>;

export const CreateApiKeyModal = ({
  isOpen,
  onClose,
  onSuccess,
}: CreateApiKeyModalProps) => {
  const { toast } = useToast();

  const form = useForm<FormValues>({
    resolver: zodResolver(createApiKeySchema),
    defaultValues: {
      name: "",
      expiresInDays: DEFAULT_EXPIRY_DAYS,
    },
  });

  const onSubmitClient = async (values: FormValues) => {
    try {
      const result = await createApiKey({
        name: values.name.trim(),
        expires_at: calculateExpiryDate(parseInt(values.expiresInDays)),
      });

      if (result.error) {
        throw new Error(result.error);
      }

      if (!result.data) {
        throw new Error("Failed to create API key");
      }

      const apiKey = result.data.data.attributes.api_key;
      if (!apiKey) {
        throw new Error("Failed to retrieve API key");
      }

      form.reset();
      onSuccess(apiKey);
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
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Create API Key"
      size="lg"
    >
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmitClient)}
          className="flex flex-col gap-4"
        >
          <div className="flex w-full justify-center gap-6">
            <CustomInput
              control={form.control}
              name="name"
              type="text"
              label="Name"
              labelPlacement="outside"
              placeholder="My API Key"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.name}
            />
          </div>

          <div className="flex flex-col gap-2">
            <CustomInput
              control={form.control}
              name="expiresInDays"
              type="number"
              label="Expires in (days)"
              labelPlacement="outside"
              placeholder="365"
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.expiresInDays}
            />
          </div>

          <FormButtons
            onCancel={handleClose}
            submitText="Create API Key"
            cancelText="Cancel"
            loadingText="Processing..."
            isDisabled={!form.formState.isValid}
          />
        </form>
      </Form>
    </CustomAlertModal>
  );
};
