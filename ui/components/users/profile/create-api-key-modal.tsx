"use client";

import { Input } from "@heroui/input";
import { ModalFooter } from "@heroui/modal";

import { createApiKey } from "@/actions/api-keys/api-keys";
import { type EnrichedApiKey } from "@/actions/api-keys/models";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";
import { CustomButton } from "@/components/ui/custom/custom-button";

import { DEFAULT_EXPIRY_DAYS } from "./api-keys/constants";
import { useModalForm } from "./api-keys/use-modal-form";
import { calculateExpiryDate, isApiKeyNameDuplicate } from "./api-keys/utils";

interface CreateApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (apiKey: string) => void;
  existingApiKeys: EnrichedApiKey[];
}

interface CreateApiKeyFormData {
  name: string;
  expiresInDays: string;
}

export const CreateApiKeyModal = ({
  isOpen,
  onClose,
  onSuccess,
  existingApiKeys,
}: CreateApiKeyModalProps) => {
  const { formData, setFormData, isLoading, error, handleSubmit, handleClose } =
    useModalForm<CreateApiKeyFormData>({
      initialData: {
        name: "",
        expiresInDays: DEFAULT_EXPIRY_DAYS,
      },
      onSubmit: async (data) => {
        if (!data.name.trim()) {
          throw new Error("Name is required");
        }

        if (isApiKeyNameDuplicate(data.name, existingApiKeys)) {
          throw new Error(
            "An API key with this name already exists. Please choose a different name.",
          );
        }

        const result = await createApiKey({
          name: data.name.trim(),
          expires_at: calculateExpiryDate(parseInt(data.expiresInDays)),
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

        onSuccess(apiKey);
      },
      onClose,
    });

  return (
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Create API Key"
      size="lg"
    >
      <div className="flex flex-col gap-4">
        <Input
          label="Name"
          labelPlacement="inside"
          variant="bordered"
          placeholder="My API Key"
          value={formData.name}
          onChange={(e) =>
            setFormData((prev) => ({ ...prev, name: e.target.value }))
          }
          isRequired
          description="A descriptive name to identify this API key"
          classNames={{
            label: "tracking-tight font-light !text-default-500 text-xs z-0!",
            input: "text-default-500 text-small",
          }}
        />

        <Input
          label="Expires in (days)"
          labelPlacement="inside"
          variant="bordered"
          type="number"
          value={formData.expiresInDays}
          onChange={(e) =>
            setFormData((prev) => ({ ...prev, expiresInDays: e.target.value }))
          }
          min="1"
          max="3650"
          description="Number of days until this key expires (default: 365)"
          classNames={{
            label: "tracking-tight font-light !text-default-500 text-xs z-0!",
            input: "text-default-500 text-small",
          }}
        />

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>

      <ModalFooter>
        <CustomButton
          ariaLabel="Cancel"
          color="transparent"
          variant="light"
          onPress={handleClose}
        >
          Cancel
        </CustomButton>
        <CustomButton
          ariaLabel="Create API Key"
          color="action"
          onPress={handleSubmit}
          isLoading={isLoading}
          isDisabled={!formData.name.trim()}
        >
          Create API Key
        </CustomButton>
      </ModalFooter>
    </CustomAlertModal>
  );
};
