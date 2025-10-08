"use client";

import { useEffect, useState } from "react";

import { Button } from "@heroui/button";
import { Input } from "@heroui/input";
import {
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/modal";

import { updateApiKey } from "@/actions/api-keys/api-keys";
import { ApiKeyData } from "@/types/api-keys";

interface EditApiKeyNameModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: ApiKeyData | null;
  onSuccess: () => void;
}

export const EditApiKeyNameModal = ({
  isOpen,
  onClose,
  apiKey,
  onSuccess,
}: EditApiKeyNameModalProps) => {
  const [name, setName] = useState(apiKey?.attributes.name || "");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sync the name state when apiKey changes or modal opens
  useEffect(() => {
    if (isOpen && apiKey) {
      setName(apiKey.attributes.name || "");
    }
  }, [isOpen, apiKey]);

  const handleSubmit = async () => {
    if (!apiKey || !name.trim()) {
      setError("Name is required");
      return;
    }

    setIsLoading(true);
    setError(null);

    const result = await updateApiKey(apiKey.id, { name: name.trim() });

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
    setName(apiKey?.attributes.name || "");
    setError(null);
    onClose();
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">
          Edit API Key Name
        </ModalHeader>
        <ModalBody>
          <div className="flex flex-col gap-4">
            <div className="text-sm text-slate-400">
              Prefix: {apiKey?.attributes.prefix}
            </div>

            <Input
              label="Name"
              placeholder="My API Key"
              value={name}
              onChange={(e) => setName(e.target.value)}
              isRequired
              autoFocus
            />

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
            color="success"
            onPress={handleSubmit}
            isLoading={isLoading}
            isDisabled={!name.trim()}
          >
            Save Changes
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};
