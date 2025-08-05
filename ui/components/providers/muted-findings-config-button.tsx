"use client";

import { SettingsIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { MutedFindingsConfigForm } from "./forms";

interface MutedFindingsConfigButtonProps {
  isDisabled?: boolean;
  autoOpen?: boolean;
  hideButton?: boolean;
}

export const MutedFindingsConfigButton = ({
  isDisabled = false,
  autoOpen = false,
  hideButton = false,
}: MutedFindingsConfigButtonProps) => {
  const [isOpen, setIsOpen] = useState(autoOpen);
  const router = useRouter();
  const searchParams = useSearchParams();

  const handleCancel = () => {
    setIsOpen(false);
    // Remove the mutelist parameter from URL when cancel is clicked
    const hasMutelistParam = searchParams.get("mutelist") === "true";
    if (hasMutelistParam) {
      router.replace("/providers");
    }
  };

  const handleOpenModal = () => {
    if (!isDisabled) {
      setIsOpen(true);
    }
  };

  const handleOpenChange = (open: boolean) => {
    setIsOpen(open);
    if (!open && autoOpen) {
      // Remove the mutelist parameter from URL when modal is closed
      router.replace("/providers");
    }
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isOpen}
        onOpenChange={handleOpenChange}
        title="Configure Mutelist"
        size="3xl"
      >
        <MutedFindingsConfigForm
          setIsOpen={setIsOpen}
          onCancel={handleCancel}
        />
      </CustomAlertModal>

      {!hideButton && (
        <CustomButton
          ariaLabel="Configure Mutelist"
          variant="dashed"
          color="warning"
          size="md"
          startContent={<SettingsIcon size={20} />}
          onPress={handleOpenModal}
          isDisabled={isDisabled}
        >
          Configure Mutelist
        </CustomButton>
      )}
    </>
  );
};
