"use client";

import { revokeApiKey } from "@/actions/api-keys/api-keys";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";

import { FALLBACK_VALUES } from "./api-keys/constants";
import { ModalButtons } from "./api-keys/modal-buttons";
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
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Revoke API Key"
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
          <p>Are you sure you want to revoke this API key?</p>
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

      <ModalButtons
        onCancel={handleClose}
        onSubmit={handleSubmit}
        isLoading={isLoading}
        isDisabled={!apiKey}
        submitText="Revoke API Key"
        submitColor="danger"
      />
    </CustomAlertModal>
  );
};
