"use client";

import { Snippet } from "@heroui/snippet";

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";
import { CustomButton } from "@/components/ui/custom/custom-button";

interface ApiKeySuccessModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: string;
}

export const ApiKeySuccessModal = ({
  isOpen,
  onClose,
  apiKey,
}: ApiKeySuccessModalProps) => {
  return (
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={(open) => !open && onClose()}
      title="API Key Created Successfully"
      size="2xl"
    >
      <div className="flex flex-col gap-4">
        <Alert variant="destructive">
          <AlertTitle>⚠️ Warning</AlertTitle>
          <AlertDescription>
            This is the only time you will see this API key. Please copy it now
            and store it securely. Once you close this dialog, the key cannot be
            retrieved again.
          </AlertDescription>
        </Alert>

        <div className="flex flex-col gap-2">
          <p className="text-sm font-medium">Your API Key</p>
          <Snippet
            hideSymbol
            classNames={{
              pre: "font-mono text-sm break-all whitespace-pre-wrap",
            }}
            tooltipProps={{
              content: "Copy API key",
              color: "default",
            }}
          >
            {apiKey}
          </Snippet>
        </div>
      </div>

      <CustomButton
        ariaLabel="Close and confirm API key saved"
        color="action"
        onPress={onClose}
      >
        Acknowledged
      </CustomButton>
    </CustomAlertModal>
  );
};
