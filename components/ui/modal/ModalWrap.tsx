"use client";

import { Button, useDisclosure } from "@nextui-org/react";
import React from "react";

import { Modal } from "@/components";

interface ModalWrapProps {
  title: string;
  body: React.ReactNode;
  closeText?: string;
  actionText?: string;
  onAction?: () => void;
  triggerText?: string;
  isDismissable?: boolean;
}

export const ModalWrap: React.FC<ModalWrapProps> = ({
  title,
  body,
  closeText = "Close",
  actionText = "Save",
  onAction,
  isDismissable = true,
  triggerText = "Open",
}) => {
  const { isOpen, onOpen, onClose, onOpenChange } = useDisclosure();
  const closeOnAction = () => {
    onAction && onAction();
    onClose();
  };

  return (
    <>
      <Button onPress={onOpen}>{triggerText}</Button>
      <Modal
        title={title}
        body={body}
        closeText={closeText}
        actionText={actionText}
        onAction={closeOnAction}
        isDismissable={isDismissable}
        isOpen={isOpen}
        onOpenChange={onOpenChange}
      />
    </>
  );
};
