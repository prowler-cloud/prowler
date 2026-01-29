"use client";

import { Snippet } from "@heroui/snippet";

import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";

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
    <Modal
      open={isOpen}
      onOpenChange={(open) => !open && onClose()}
      title="API Key Created Successfully"
    >
      <div className="flex flex-col gap-6">
        <Alert variant="destructive">
          <AlertDescription>
            This is the only time you will see this API key. Please copy it now
            and store it securely. Once you close this dialog, the key cannot be
            retrieved again.
          </AlertDescription>
        </Alert>

        <div className="flex flex-col gap-2">
          <p className="text-text-neutral-primary text-sm font-medium">
            Your API Key
          </p>
          <Snippet
            hideSymbol
            classNames={{
              pre: "font-mono text-sm break-all whitespace-pre-wrap p-2 text-text-neutral-primary",
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

      <div className="mt-4 flex justify-end">
        <Button aria-label="Close and confirm API key saved" onClick={onClose}>
          Acknowledged
        </Button>
      </div>
    </Modal>
  );
};
