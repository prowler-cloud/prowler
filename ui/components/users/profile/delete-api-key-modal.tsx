"use client";

import { ModalFooter } from "@heroui/modal";

import { revokeApiKey } from "@/actions/api-keys/api-keys";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";
import { CustomButton } from "@/components/ui/custom/custom-button";

import { FALLBACK_VALUES } from "./api-keys/constants";
import { ApiKeyData } from "./api-keys/types";
import { useModalForm } from "./api-keys/use-modal-form";

interface DeleteApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: ApiKeyData | null;
  onSuccess: () => void;
}

export const DeleteApiKeyModal = ({
  isOpen,
  onClose,
  apiKey,
  onSuccess,
}: DeleteApiKeyModalProps) => {
  const { isLoading, error, handleSubmit, handleClose } = useModalForm({
    initialData: {},
    onSubmit: async () => {
      if (!apiKey) {
        throw new Error("No API key selected");
      }

      const result = await revokeApiKey(apiKey.id);

      if (result.error) {
        throw new Error(result.error);
      }

      onSuccess();
    },
    onSuccess,
    onClose,
  });

  return (
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Delete API Key"
      size="lg"
    >
      <div className="flex flex-col gap-4">
        <Alert variant="destructive">
          <AlertTitle className="text-danger-700">⚠️ Warning</AlertTitle>
          <AlertDescription className="text-danger-600">
            This action cannot be undone. This API key will be revoked and will
            no longer work.
          </AlertDescription>
        </Alert>

        <div className="text-sm">
          <p>Are you sure you want to delete this API key?</p>
          <div className="mt-2 rounded-lg bg-slate-800 p-3">
            <p className="font-medium text-white">
              {apiKey?.attributes.name || FALLBACK_VALUES.UNNAMED_KEY}
            </p>
            <p className="mt-1 text-xs text-slate-400">
              Prefix: {apiKey?.attributes.prefix}
            </p>
          </div>
        </div>

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
          ariaLabel="Revoke API Key"
          color="danger"
          onPress={handleSubmit}
          isLoading={isLoading}
          isDisabled={!apiKey}
        >
          Revoke API Key
        </CustomButton>
      </ModalFooter>
    </CustomAlertModal>
  );
};
