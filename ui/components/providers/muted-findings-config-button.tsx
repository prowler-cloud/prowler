"use client";

import { SettingsIcon } from "lucide-react";
import { usePathname } from "next/navigation";
import { useEffect } from "react";

import { Button } from "@/components/shadcn";
import { CustomAlertModal } from "@/components/ui/custom";
import { useUIStore } from "@/store/ui/store";

import { MutedFindingsConfigForm } from "./forms";

export const MutedFindingsConfigButton = () => {
  const pathname = usePathname();
  const {
    isMutelistModalOpen,
    openMutelistModal,
    closeMutelistModal,
    hasProviders,
    shouldAutoOpenMutelist,
    resetMutelistModalRequest,
  } = useUIStore();

  useEffect(() => {
    if (!shouldAutoOpenMutelist) {
      return;
    }

    if (pathname !== "/providers") {
      return;
    }

    if (hasProviders) {
      openMutelistModal();
    }

    resetMutelistModalRequest();
  }, [
    hasProviders,
    openMutelistModal,
    pathname,
    resetMutelistModalRequest,
    shouldAutoOpenMutelist,
  ]);

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

      <Button
        variant="outline"
        onClick={handleOpenModal}
        disabled={!hasProviders}
      >
        <SettingsIcon size={20} />
        Configure Mutelist
      </Button>
    </>
  );
};
