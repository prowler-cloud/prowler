"use client";

import { SettingsIcon } from "lucide-react";
import { Suspense, useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { SSRMutedFindingsConfigFormWrapper } from "./forms";

interface MutedFindingsConfigButtonProps {
  isDisabled?: boolean;
}

export const MutedFindingsConfigButton = ({
  isDisabled = false,
}: MutedFindingsConfigButtonProps) => {
  const [isOpen, setIsOpen] = useState(false);

  const handleOpenModal = () => {
    if (!isDisabled) {
      setIsOpen(true);
    }
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isOpen}
        onOpenChange={setIsOpen}
        title="Configure Muted Findings"
        size="3xl"
      >
        <Suspense
          fallback={
            <div className="flex flex-col items-center justify-center space-y-4 py-8">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
              <p className="text-sm text-default-600">
                Loading configuration...
              </p>
            </div>
          }
        >
          <SSRMutedFindingsConfigFormWrapper
            setIsOpen={setIsOpen}
            onConfigDeleted={() => {}}
          />
        </Suspense>
      </CustomAlertModal>

      <CustomButton
        ariaLabel="Configure Muted Findings"
        variant="dashed"
        color="warning"
        size="md"
        startContent={<SettingsIcon size={20} />}
        onPress={handleOpenModal}
        isDisabled={isDisabled}
      >
        Configure Muted Findings
      </CustomButton>
    </>
  );
};
