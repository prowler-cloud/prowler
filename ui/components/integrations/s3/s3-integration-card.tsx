"use client";

import { Card, CardBody, CardHeader } from "@nextui-org/react";
import { SettingsIcon } from "lucide-react";

import { AmazonS3Icon } from "@/components/icons/services/IconServices";
import { CustomButton } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";

export const S3IntegrationCard = () => {
  return (
    <Card className="dark:bg-gray-800">
      <CardHeader className="gap-2">
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <AmazonS3Icon size={40} />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                Amazon S3
              </h4>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-nowrap text-xs text-gray-500 dark:text-gray-300">
                  Export security findings to Amazon S3 buckets.
                </p>
                <CustomLink
                  href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-s3-integration/"
                  aria-label="Learn more about S3 integration"
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
              asLink="/integrations/amazon-s3"
              ariaLabel="Manage S3 integrations"
            >
              Manage
            </CustomButton>
          </div>
        </div>
      </CardHeader>
      <CardBody>
        <div className="flex flex-col gap-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure and manage your Amazon S3 integrations to automatically
            export security findings to your S3 buckets.
          </p>
        </div>
      </CardBody>
    </Card>
  );
};
