"use client";

import { Input } from "@heroui/input";
import { ModalFooter } from "@heroui/modal";
import { useEffect } from "react";

import { updateApiKey } from "@/actions/api-keys/api-keys";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";
import { CustomButton } from "@/components/ui/custom/custom-button";

import { ApiKeyData } from "./api-keys/types";
import { useModalForm } from "./api-keys/use-modal-form";

interface EditApiKeyNameModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: ApiKeyData | null;
  onSuccess: () => void;
}

interface EditApiKeyFormData {
  name: string;
}

export const EditApiKeyNameModal = ({
  isOpen,
  onClose,
  apiKey,
  onSuccess,
}: EditApiKeyNameModalProps) => {
  const { formData, setFormData, isLoading, error, handleSubmit, handleClose } =
    useModalForm<EditApiKeyFormData>({
      initialData: {
        name: apiKey?.attributes.name || "",
      },
      onSubmit: async (data) => {
        if (!apiKey || !data.name.trim()) {
          throw new Error("Name is required");
        }

        const result = await updateApiKey(apiKey.id, {
          name: data.name.trim(),
        });

        if (result.error) {
          throw new Error(result.error);
        }

        onSuccess();
      },
      onSuccess,
      onClose,
    });

  // Sync form data when apiKey changes or modal opens
  useEffect(() => {
    if (isOpen && apiKey) {
      setFormData({ name: apiKey.attributes.name || "" });
    }
  }, [isOpen, apiKey, setFormData]);

  return (
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Edit API Key Name"
      size="lg"
    >
      <div className="flex flex-col gap-4">
        <div className="text-sm text-slate-400">
          Prefix: {apiKey?.attributes.prefix}
        </div>

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
          ariaLabel="Save changes"
          color="action"
          onPress={handleSubmit}
          isLoading={isLoading}
          isDisabled={!formData.name.trim()}
        >
          Save Changes
        </CustomButton>
      </ModalFooter>
    </CustomAlertModal>
  );
};
