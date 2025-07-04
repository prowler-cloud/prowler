import { Modal, ModalBody, ModalContent, ModalHeader } from "@nextui-org/react";
import React, { ReactNode } from "react";

interface CustomAlertModalProps {
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  title?: string;
  description?: string;
  children: ReactNode;
  size?: "sm" | "md" | "lg" | "xl" | "2xl" | "3xl" | "4xl" | "5xl";
}

export const CustomAlertModal: React.FC<CustomAlertModalProps> = ({
  isOpen,
  onOpenChange,
  title,
  description,
  children,
  size = "xl",
}) => {
  return (
    <Modal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      size={size}
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
              {description && (
                <p className="text-small text-gray-600 dark:text-gray-300">
                  {description}
                </p>
              )}
              {children}
            </ModalBody>
          </>
        )}
      </ModalContent>
    </Modal>
  );
};
