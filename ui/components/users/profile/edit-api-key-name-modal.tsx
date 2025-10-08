"use client";

import { Button } from "@heroui/button";
import { Input } from "@heroui/input";
import { ModalFooter } from "@heroui/modal";
import { useCallback, useEffect, useState } from "react";

import { updateApiKey } from "@/actions/api-keys/api-keys";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";

import { ApiKeyData } from "./api-keys/types";

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

  const resetForm = useCallback(() => {
    setName(apiKey?.attributes.name || "");
    setError(null);
  }, [apiKey?.attributes.name]);

  // Sync the name state when apiKey changes or modal opens
  useEffect(() => {
    if (isOpen && apiKey) {
      resetForm();
    }
  }, [isOpen, apiKey, resetForm]);

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
          value={name}
          onChange={(e) => setName(e.target.value)}
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
    </CustomAlertModal>
  );
};
