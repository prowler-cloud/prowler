"use client";

import { Button } from "@heroui/button";
import {
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/modal";
import { Snippet } from "@heroui/snippet";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert/Alert";

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
    <Modal isOpen={isOpen} onClose={onClose} size="2xl" isDismissable={false}>
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">
          API Key Created Successfully
        </ModalHeader>
        <ModalBody>
          <div className="flex flex-col gap-4">
            <Alert className="bg-warning-50 text-warning-700 border-warning-200">
              <AlertTitle>⚠️ Important</AlertTitle>
              <AlertDescription>
                This is the only time you will see this API key. Please copy it
                now and store it securely. Once you close this dialog, the key
                cannot be retrieved again.
              </AlertDescription>
            </Alert>

            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Your API Key</p>
              <Snippet
                symbol=""
                classNames={{
                  base: "bg-slate-800 border border-slate-700",
                  pre: "font-mono text-sm text-white break-all whitespace-pre-wrap",
                  copyButton: "text-slate-400",
                }}
                tooltipProps={{
                  content: "Copy API key",
                  color: "default",
                }}
              >
                {apiKey}
              </Snippet>
            </div>

            <div className="rounded-lg bg-slate-800 p-4 text-sm text-slate-300">
              <div className="mb-2 font-medium text-white">How to use:</div>
              <code className="block text-xs break-all">
                Authorization: Api-Key {apiKey}
              </code>
            </div>
          </div>
        </ModalBody>
        <ModalFooter>
          <Button color="success" onPress={onClose}>
            I have saved my API key
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};
