"use client";

import { SettingsIcon } from "lucide-react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";
import { useUIStore } from "@/store/ui/store";

import { MutedFindingsConfigForm } from "./forms";

export const MutedFindingsConfigButton = () => {
  const {
    isMutelistModalOpen,
    openMutelistModal,
    closeMutelistModal,
    hasProviders,
  } = useUIStore();

  const handleOpenModal = () => {
    if (hasProviders) {
      openMutelistModal();
    }
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isMutelistModalOpen}
        onOpenChange={closeMutelistModal}
        title="Configure Mutelist"
        size="3xl"
      >
        <MutedFindingsConfigForm
          setIsOpen={closeMutelistModal}
          onCancel={closeMutelistModal}
        />
      </CustomAlertModal>

      <CustomButton
        ariaLabel="Configure Mutelist"
        variant="dashed"
        color="warning"
        size="md"
        startContent={<SettingsIcon size={20} />}
        onPress={handleOpenModal}
        isDisabled={!hasProviders}
      >
        Configure Mutelist
      </CustomButton>
    </>
  );
};
