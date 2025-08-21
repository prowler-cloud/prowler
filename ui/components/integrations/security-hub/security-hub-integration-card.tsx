"use client";

import { Card, CardBody, CardHeader } from "@nextui-org/react";
import { SettingsIcon } from "lucide-react";

import { AWSSecurityHubIcon } from "@/components/icons/services/IconServices";
import { CustomButton } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";

export const SecurityHubIntegrationCard = () => {
  return (
    <Card className="dark:bg-gray-800">
      <CardHeader className="gap-2">
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <AWSSecurityHubIcon size={40} />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                AWS Security Hub
              </h4>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-nowrap text-xs text-gray-500 dark:text-gray-300">
                  Send security findings to AWS Security Hub.
                </p>
                <CustomLink
                  href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/securityhub/"
                  aria-label="Learn more about Security Hub integration"
                  size="xs"
                >
                  Learn more
                </CustomLink>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <CustomButton
              size="sm"
              variant="bordered"
              startContent={<SettingsIcon size={14} />}
              asLink="/integrations/securityhub"
              ariaLabel="Manage Security Hub integrations"
            >
              Manage
            </CustomButton>
          </div>
        </div>
      </CardHeader>
      <CardBody>
        <div className="flex flex-col gap-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure and manage your AWS Security Hub integrations to
            automatically send security findings to Security Hub for centralized
            monitoring.
          </p>
        </div>
      </CardBody>
    </Card>
  );
};
