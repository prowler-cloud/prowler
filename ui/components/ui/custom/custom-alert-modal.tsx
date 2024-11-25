import { Modal, ModalBody, ModalContent, ModalHeader } from "@nextui-org/react";
import React, { ReactNode } from "react";

interface CustomAlertModalProps {
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  title?: string;
  description?: string;
  children: ReactNode;
  className?: string;
}

export const CustomAlertModal: React.FC<CustomAlertModalProps> = ({
  isOpen,
  onOpenChange,
  title,
  description,
  children,
  className,
}) => {
  return (
    <Modal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      size="xl"
      className={`dark:bg-prowler-blue-800 ${className || ""}`}
      backdrop="blur"
    >
      <ModalContent className="py-4">
        {(_onClose) => (
          <>
            <ModalHeader className="flex flex-col py-0">{title}</ModalHeader>
            <ModalBody>
              {description}
              {children}
            </ModalBody>
          </>
        )}
      </ModalContent>
    </Modal>
  );
};
