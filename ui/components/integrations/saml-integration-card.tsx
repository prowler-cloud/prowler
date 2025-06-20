"use client";

import { Card, CardBody, CardHeader } from "@nextui-org/react";
import { CheckIcon } from "lucide-react";
import { useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { SamlConfigForm } from "./forms";

export const SamlIntegrationCard = ({ isEnabled }: { isEnabled: boolean }) => {
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

      <Card className="dark:bg-prowler-blue-400">
        <CardHeader className="gap-2">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <h4 className="text-lg font-bold">SAML SSO Integration</h4>
              {isEnabled && (
                <CheckIcon className="text-prowler-green" size={20} />
              )}
            </div>
            <p className="text-xs text-gray-500">
              {isEnabled
                ? "SAML Single Sign-On is enabled for this organization"
                : "Configure SAML Single Sign-On for secure authentication"}
            </p>
          </div>
        </CardHeader>
        <CardBody>
          <div className="flex items-center justify-between">
            <div className="text-sm">
              <span className="font-medium">Status: </span>
              <span
                className={isEnabled ? "text-prowler-green" : "text-gray-500"}
              >
                {isEnabled ? "Enabled" : "Disabled"}
              </span>
            </div>
            <CustomButton
              size="sm"
              ariaLabel="Add SAML SSO"
              color="action"
              onPress={() => setIsSamlModalOpen(true)}
            >
              {isEnabled ? "Update" : "Enable"}
            </CustomButton>
          </div>
        </CardBody>
      </Card>
    </>
  );
};
