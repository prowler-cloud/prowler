"use client";

import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";

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
          <CodeSnippet
            value={apiKey}
            multiline
            ariaLabel="Copy API key"
            className="w-full px-3 py-2 text-sm"
          />
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
