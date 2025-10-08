"use client";

import { useState } from "react";

import { Button } from "@heroui/button";
import {
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/modal";
import { Check, Copy } from "lucide-react";

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
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy:", error);
    }
  };

  const handleClose = () => {
    setCopied(false);
    onClose();
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="2xl" isDismissable={false}>
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">
          API Key Created Successfully
        </ModalHeader>
        <ModalBody>
          <div className="flex flex-col gap-4">
            <div className="rounded-lg bg-warning-50 p-4 text-sm text-warning-700">
              <div className="flex items-start gap-2">
                <div className="mt-0.5">⚠️</div>
                <div>
                  <strong>Important:</strong> This is the only time you will see
                  this API key. Please copy it now and store it securely. Once you
                  close this dialog, the key cannot be retrieved again.
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-sm font-medium">Your API Key</label>
              <div className="flex items-center gap-2">
                <div className="flex-1 overflow-hidden rounded-lg border border-slate-700 bg-slate-800 p-3">
                  <code className="break-all text-sm font-mono text-white">
                    {apiKey}
                  </code>
                </div>
                <Button
                  isIconOnly
                  color={copied ? "success" : "default"}
                  variant="flat"
                  onPress={handleCopy}
                  className="shrink-0"
                >
                  {copied ? <Check size={18} /> : <Copy size={18} />}
                </Button>
              </div>
            </div>

            <div className="rounded-lg bg-slate-800 p-4 text-sm text-slate-300">
              <div className="font-medium text-white mb-2">How to use:</div>
              <code className="block break-all text-xs">
                Authorization: Api-Key {apiKey}
              </code>
            </div>
          </div>
        </ModalBody>
        <ModalFooter>
          <Button color="success" onPress={handleClose}>
            I have saved my API key
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};
