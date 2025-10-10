"use client";

import { useEffect } from "react";

import { updateApiKey } from "@/actions/api-keys/api-keys";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";

import { ModalButtons } from "./api-keys/modal-buttons";
import { EnrichedApiKey } from "./api-keys/types";
import { useModalForm } from "./api-keys/use-modal-form";
import { isApiKeyNameDuplicate } from "./api-keys/utils";

interface EditApiKeyNameModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: EnrichedApiKey | null;
  onSuccess: () => void;
  existingApiKeys: EnrichedApiKey[];
}

interface EditApiKeyFormData {
  name: string;
}

export const EditApiKeyNameModal = ({
  isOpen,
  onClose,
  apiKey,
  onSuccess,
  existingApiKeys,
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

        if (isApiKeyNameDuplicate(data.name, existingApiKeys, apiKey.id)) {
          throw new Error(
            "An API key with this name already exists. Please choose a different name.",
          );
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

        <div className="flex flex-col gap-2">
          <label
            htmlFor="edit-api-key-name"
            className="text-sm font-medium text-slate-300"
          >
            Name <span className="text-danger">*</span>
          </label>
          <input
            id="edit-api-key-name"
            type="text"
            placeholder="My API Key"
            value={formData.name}
            onChange={(e) =>
              setFormData((prev) => ({ ...prev, name: e.target.value }))
            }
            className="focus:border-prowler-theme-green focus:ring-prowler-theme-green rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 focus:ring-1 focus:outline-none"
            required
          />
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>

      <ModalButtons
        onCancel={handleClose}
        onSubmit={handleSubmit}
        isLoading={isLoading}
        isDisabled={!formData.name.trim()}
        submitText="Save Changes"
      />
    </CustomAlertModal>
  );
};
