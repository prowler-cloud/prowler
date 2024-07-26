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
  modalTitle: string;
  modalBody: React.ReactNode;
  closeButtonLabel?: string;
  actionButtonLabel?: string;
  onAction: () => void;
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  isDismissable?: boolean;
  isKeyboardDismissDisabled?: boolean;
  hideCloseButton?: boolean;
}

export const Modal: React.FC<ModalProps> = ({
  modalTitle,
  modalBody,
  closeButtonLabel,
  actionButtonLabel,
  onAction,
  isOpen,
  onOpenChange,
  isDismissable,
}) => {
  return (
    <>
      <ModalContainer
        isOpen={isOpen}
        onOpenChange={onOpenChange}
        backdrop="blur"
        isDismissable={isDismissable}
        isKeyboardDismissDisabled={!isDismissable}
        hideCloseButton={!isDismissable}
      >
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader className="flex flex-col gap-1">
                {modalTitle}
              </ModalHeader>
              <ModalBody>{modalBody}</ModalBody>
              <ModalFooter>
                <Button color="danger" variant="light" onPress={onClose}>
                  {closeButtonLabel}
                </Button>
                <Button color="primary" onPress={onAction}>
                  {actionButtonLabel}
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </ModalContainer>
    </>
  );
};
