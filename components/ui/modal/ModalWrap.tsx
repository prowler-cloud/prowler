"use client";

import { Button, useDisclosure } from "@nextui-org/react";
import React from "react";

import { Modal } from "@/components";

interface ModalWrapProps {
  modalTitle: string;
  modalBody: React.ReactNode;
  closeButtonLabel?: string;
  actionButtonLabel?: string;
  onAction: () => void;
  openButtonLabel?: string;
  isDismissable?: boolean;
}

export const ModalWrap: React.FC<ModalWrapProps> = ({
  modalTitle,
  modalBody,
  closeButtonLabel = "Close",
  actionButtonLabel = "Save",
  onAction,
  openButtonLabel = "Open",
  isDismissable = true,
}) => {
  const { isOpen, onOpen, onClose, onOpenChange } = useDisclosure();
  const closeOnAction = () => {
    onAction?.();
    onClose();
  };

  return (
    <>
      <Button onPress={onOpen}>{openButtonLabel}</Button>
      <Modal
        modalTitle={modalTitle}
        modalBody={modalBody}
        closeButtonLabel={closeButtonLabel}
        actionButtonLabel={actionButtonLabel}
        onAction={closeOnAction}
        isDismissable={isDismissable}
        isOpen={isOpen}
        onOpenChange={onOpenChange}
      />
    </>
  );
};
