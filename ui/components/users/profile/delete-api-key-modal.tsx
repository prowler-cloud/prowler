"use client";

import { useState } from "react";

import { Button } from "@heroui/button";
import {
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/modal";

import { revokeApiKey } from "@/actions/api-keys/api-keys";
import { ApiKeyData } from "@/types/api-keys";

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

    setError(null);
    onSuccess();
    onClose();
  };

  const handleClose = () => {
    setError(null);
    onClose();
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">Delete API Key</ModalHeader>
        <ModalBody>
          <div className="flex flex-col gap-4">
            <div className="rounded-lg bg-danger-50 p-4 text-sm text-danger-700">
              <div className="flex items-start gap-2">
                <div className="mt-0.5">⚠️</div>
                <div>
                  <strong>Warning:</strong> This action cannot be undone. This
                  API key will be revoked and will no longer work.
                </div>
              </div>
            </div>

            <div className="text-sm">
              <p>Are you sure you want to delete this API key?</p>
              <div className="mt-2 rounded-lg bg-slate-800 p-3">
                <p className="font-medium text-white">
                  {apiKey?.attributes.name || "Unnamed Key"}
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Prefix: {apiKey?.attributes.prefix}
                </p>
              </div>
            </div>

            {error && (
              <div className="rounded-lg bg-danger-50 p-3 text-sm text-danger-600">
                {error}
              </div>
            )}
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
