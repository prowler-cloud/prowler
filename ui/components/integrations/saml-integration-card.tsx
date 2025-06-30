"use client";

import { Card, CardBody, CardHeader } from "@nextui-org/react";
import { Link } from "@nextui-org/react";
import { CheckIcon } from "lucide-react";
import { useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { SamlConfigForm } from "./forms";

export const SamlIntegrationCard = ({ id }: { id: string }) => {
  const [isSamlModalOpen, setIsSamlModalOpen] = useState(false);

  return (
    <>
      <CustomAlertModal
        isOpen={isSamlModalOpen}
        onOpenChange={setIsSamlModalOpen}
        title="Configure SAML SSO"
      >
        <SamlConfigForm setIsOpen={setIsSamlModalOpen} id={id} />
      </CustomAlertModal>

      <Card className="dark:bg-prowler-blue-400">
        <CardHeader className="gap-2">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <h4 className="text-lg font-bold">SAML SSO Integration</h4>
              {id && <CheckIcon className="text-prowler-green" size={20} />}
            </div>
            <p className="text-xs text-gray-500">
              {id ? (
                "SAML Single Sign-On is enabled for this organization"
              ) : (
                <>
                  Configure SAML Single Sign-On for secure authentication.{" "}
                  <Link
                    target="_blank"
                    href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-sso"
                    rel="noopener noreferrer"
                    className="text-xs font-medium text-primary"
                  >
                    Read the docs
                  </Link>
                </>
              )}
            </p>
          </div>
        </CardHeader>
        <CardBody>
          <div className="flex items-center justify-between">
            <div className="text-sm">
              <span className="font-medium">Status: </span>
              <span className={id ? "text-prowler-green" : "text-gray-500"}>
                {id ? "Enabled" : "Disabled"}
              </span>
            </div>
            <CustomButton
              size="sm"
              ariaLabel="Add SAML SSO"
              color="action"
              onPress={() => setIsSamlModalOpen(true)}
            >
              {id ? "Update" : "Enable"}
            </CustomButton>
          </div>
        </CardBody>
      </Card>
    </>
  );
};
