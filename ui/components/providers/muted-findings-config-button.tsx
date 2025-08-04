"use client";

import { SettingsIcon } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { MutedFindingsConfigForm } from "./forms";

interface MutedFindingsConfigButtonProps {
  isDisabled?: boolean;
}

export const MutedFindingsConfigButton = ({
  isDisabled = false,
}: MutedFindingsConfigButtonProps) => {
  const searchParams = useSearchParams();

  const isOpen = searchParams.get("modal") === "mutelist";

  const handleOpenModal = () => {
    if (!isDisabled) {
      const params = new URLSearchParams(window.location.search);
      params.set("modal", "mutelist");
      window.history.pushState({}, "", `?${params.toString()}`);
    }
  };

  const handleModalClose = () => {
    const params = new URLSearchParams(window.location.search);
    params.delete("modal");
    window.history.pushState({}, "", `?${params.toString()}`);
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isOpen}
        onOpenChange={handleModalClose}
        title="Configure Mutelist"
        size="3xl"
      >
        <MutedFindingsConfigForm onCancel={handleModalClose} />
      </CustomAlertModal>

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
    </>
  );
};
