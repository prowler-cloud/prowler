"use client";

import { useState } from "react";

import { Button } from "@heroui/button";
import { Input } from "@heroui/input";
import {
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/modal";

import { createApiKey } from "@/actions/api-keys/api-keys";

interface CreateApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (apiKey: string) => void;
}

export const CreateApiKeyModal = ({
  isOpen,
  onClose,
  onSuccess,
}: CreateApiKeyModalProps) => {
  const [name, setName] = useState("");
  const [expiresInDays, setExpiresInDays] = useState("365");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!name.trim()) {
      setError("Name is required");
      return;
    }

    setIsLoading(true);
    setError(null);

    // Calculate expiration date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + parseInt(expiresInDays));

    const result = await createApiKey({
      name: name.trim(),
      expires_at: expiresAt.toISOString(),
    });

    setIsLoading(false);

    if (result.error) {
      setError(result.error);
      return;
    }

    // Extract the full API key from the response
    const apiKey = result.data.data.attributes.api_key;
    if (!apiKey) {
      setError("Failed to retrieve API key");
      return;
    }

    // Reset form
    setName("");
    setExpiresInDays("365");
    setError(null);

    // Show success modal with the API key
    onSuccess(apiKey);
    onClose();
  };

  const handleClose = () => {
    setName("");
    setExpiresInDays("365");
    setError(null);
    onClose();
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">
          Create API Key
        </ModalHeader>
        <ModalBody>
          <div className="flex flex-col gap-4">
            <Input
              label="Name"
              placeholder="My API Key"
              value={name}
              onChange={(e) => setName(e.target.value)}
              isRequired
              description="A descriptive name to identify this API key"
              autoFocus
            />

            <Input
              label="Expires in (days)"
              type="number"
              value={expiresInDays}
              onChange={(e) => setExpiresInDays(e.target.value)}
              min="1"
              max="3650"
              description="Number of days until this key expires (default: 365)"
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
            Create API Key
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};
