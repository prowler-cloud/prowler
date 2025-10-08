"use client";

import { ModalFooter } from "@heroui/modal";
import { useState } from "react";

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
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resetForm = () => {
    setError(null);
  };

  const handleDelete = async () => {
    if (!apiKey) return;

    setIsLoading(true);
    setError(null);

    const result = await revokeApiKey(apiKey.id);

    setIsLoading(false);

    if (result.error) {
      setError(result.error);
      return;
    }

    resetForm();
    onSuccess();
    onClose();
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

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
          onPress={handleDelete}
          isLoading={isLoading}
          isDisabled={!apiKey}
        >
          Revoke API Key
        </CustomButton>
      </ModalFooter>
    </CustomAlertModal>
  );
};
