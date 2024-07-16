import {
  Button,
  Modal as ModalContainer,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@nextui-org/react";
import React from "react";

interface ModalProps {
  title: string;
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  body: React.ReactNode;
  actionText?: string;
  onAction?: () => void;
}

export const Modal: React.FC<ModalProps> = ({
  title,
  isOpen,
  onOpenChange,
  body,
  actionText,
  onAction,
}) => {
  const hasActionButton = actionText && onAction;

  return (
    <>
      <ModalContainer isOpen={isOpen} onOpenChange={onOpenChange}>
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader className="flex flex-col gap-1">{title}</ModalHeader>
              <ModalBody>{body}</ModalBody>
              <ModalFooter>
                <Button color="danger" variant="light" onPress={onClose}>
                  Close
                </Button>
                {hasActionButton && (
                  <Button color="primary" onPress={onAction}>
                    {actionText}
                  </Button>
                )}
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </ModalContainer>
    </>
  );
};
