"use client";

import { Button } from "@heroui/button";
import { Input } from "@heroui/input";
import { ModalFooter } from "@heroui/modal";
import { useState } from "react";

import { createApiKey } from "@/actions/api-keys/api-keys";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";

import { DEFAULT_EXPIRY_DAYS } from "./api-keys/constants";
import { calculateExpiryDate } from "./api-keys/utils";

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
  const [expiresInDays, setExpiresInDays] = useState(DEFAULT_EXPIRY_DAYS);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resetForm = () => {
    setName("");
    setExpiresInDays(DEFAULT_EXPIRY_DAYS);
    setError(null);
  };

  const handleSubmit = async () => {
    if (!name.trim()) {
      setError("Name is required");
      return;
    }

    setIsLoading(true);
    setError(null);

    const result = await createApiKey({
      name: name.trim(),
      expires_at: calculateExpiryDate(parseInt(expiresInDays)),
    });

    setIsLoading(false);

    if (result.error) {
      setError(result.error);
      return;
    }

    const apiKey = result.data.data.attributes.api_key;
    if (!apiKey) {
      setError("Failed to retrieve API key");
      return;
    }

    resetForm();
    onSuccess(apiKey);
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
      title="Create API Key"
      size="lg"
    >
      <div className="flex flex-col gap-4">
        <Input
          label="Name"
          labelPlacement="inside"
          variant="bordered"
          placeholder="My API Key"
          value={name}
          onChange={(e) => setName(e.target.value)}
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
          value={expiresInDays}
          onChange={(e) => setExpiresInDays(e.target.value)}
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
    </CustomAlertModal>
  );
};
