import { Modal, ModalBody, ModalContent, ModalHeader } from "@nextui-org/react";
import React, { ReactNode } from "react";

interface CustomAlertModalProps {
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  title?: string;
  description?: string;
  children: ReactNode;
}

export const CustomAlertModal: React.FC<CustomAlertModalProps> = ({
  isOpen,
  onOpenChange,
  title,
  description,
  children,
}) => {
  return (
    <Modal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      size="xl"
      classNames={{
        base: "dark:bg-prowler-blue-800",
        closeButton: "rounded-md",
      }}
      backdrop="blur"
      placement="center"
    >
      <ModalContent className="py-4">
        {(_onClose) => (
          <>
            <ModalHeader className="flex flex-col py-0">{title}</ModalHeader>
            <ModalBody>
              <p className="text-small text-gray-600 dark:text-gray-300">
                {description}
              </p>
              {children}
            </ModalBody>
          </>
        )}
      </ModalContent>
    </Modal>
  );
};
