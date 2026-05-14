"use client";

import { Trash2Icon } from "lucide-react";

import { revokeApiKey } from "@/actions/api-keys/api-keys";
import { Modal } from "@/components/shadcn/modal";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert/Alert";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { ModalButtons } from "@/components/ui/custom/custom-modal-buttons";

import { FALLBACK_VALUES } from "./api-keys/constants";
import { EnrichedApiKey } from "./api-keys/types";
import { useModalForm } from "./api-keys/use-modal-form";

interface RevokeApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: EnrichedApiKey | null;
  onSuccess: () => void;
}

export const RevokeApiKeyModal = ({
  isOpen,
  onClose,
  apiKey,
  onSuccess,
}: RevokeApiKeyModalProps) => {
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
    <Modal
      open={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Revoke API Key"
      size="lg"
    >
      <div className="flex flex-col gap-4">
        <Alert variant="destructive">
          <AlertTitle>⚠️ Warning</AlertTitle>
          <AlertDescription>
            This action cannot be undone. This API key will be revoked and will
            no longer work.
          </AlertDescription>
        </Alert>

        <div className="flex flex-col gap-2">
          <p>Are you sure you want to revoke this API key?</p>

          <CodeSnippet
            value={`${apiKey?.attributes.name || FALLBACK_VALUES.UNNAMED_KEY}\nPrefix: ${apiKey?.attributes.prefix}`}
            hideCopyButton
            multiline
            className="w-full px-3 py-2 text-sm"
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
        isDisabled={!apiKey}
        submitText="Revoke API Key"
        submitColor="danger"
        submitIcon={<Trash2Icon size={24} />}
      />
    </Modal>
  );
};
