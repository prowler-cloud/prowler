"use client";

import { Button } from "@heroui/button";
import {
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/modal";
import { useState } from "react";

import { revokeApiKey } from "@/actions/api-keys/api-keys";
import { ApiKeyData } from "@/types/api-keys";

import { FALLBACK_VALUES } from "./api-keys/constants";
import { ErrorAlert } from "./api-keys/error-alert";
import { WarningAlert } from "./api-keys/warning-alert";

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
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">
          Delete API Key
        </ModalHeader>
        <ModalBody>
          <div className="flex flex-col gap-4">
            <WarningAlert
              variant="danger"
              message="This action cannot be undone. This API key will be revoked and will no longer work."
            />

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

            <ErrorAlert error={error} />
          </div>
        </ModalBody>
        <ModalFooter>
          <Button color="default" variant="light" onPress={handleClose}>
            Cancel
          </Button>
          <Button color="danger" onPress={handleDelete} isLoading={isLoading}>
            Delete
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};
