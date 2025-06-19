"use client";

import { useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { SamlConfigForm } from "./forms";

export const SamlIntegrationCard = () => {
  const [isSamlModalOpen, setIsSamlModalOpen] = useState(false);

  return (
    <>
      <CustomAlertModal
        isOpen={isSamlModalOpen}
        onOpenChange={setIsSamlModalOpen}
        title="Configure SAML SSO"
      >
        <SamlConfigForm setIsOpen={setIsSamlModalOpen} />
      </CustomAlertModal>

      <div className="flex w-full items-center justify-between gap-4 rounded-lg bg-default-100 p-4 sm:w-1/2 lg:w-1/3 xl:w-1/4">
        <p className="whitespace-nowrap font-medium">SAML SSO</p>
        <CustomButton
          size="sm"
          ariaLabel="Add SAML SSO"
          color="action"
          onPress={() => setIsSamlModalOpen(true)}
        >
          Enable
        </CustomButton>
      </div>
    </>
  );
};
