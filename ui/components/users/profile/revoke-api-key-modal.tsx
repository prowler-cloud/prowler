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

interface RevokeApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: ApiKeyData | null;
  onSuccess: () => void;
}

export const RevokeApiKeyModal = ({
  isOpen,
  onClose,
  apiKey,
  onSuccess,
}: RevokeApiKeyModalProps) => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRevoke = async () => {
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
        <ModalHeader className="flex flex-col gap-1">Revoke API Key</ModalHeader>
        <ModalBody>
          <div className="flex flex-col gap-4">
            <div className="rounded-lg bg-danger-50 p-4 text-sm text-danger-700">
              <div className="flex items-start gap-2">
                <div className="mt-0.5">⚠️</div>
                <div>
                  <strong>Warning:</strong> This action cannot be undone. Once
                  revoked, this API key will no longer work and cannot be
                  restored.
                </div>
              </div>
            </div>

            <div className="text-sm">
              <p>Are you sure you want to revoke this API key?</p>
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
          <Button
            color="danger"
            onPress={handleRevoke}
            isLoading={isLoading}
          >
            Revoke API Key
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};
