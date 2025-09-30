"use client";

import { Card, CardBody, CardHeader } from "@heroui/card";
import { SettingsIcon } from "lucide-react";

import { JiraIcon } from "@/components/icons/services/IconServices";
import { CustomButton } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";

export const JiraIntegrationCard = () => {
  return (
    <Card className="dark:bg-gray-800">
      <CardHeader className="gap-2">
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <JiraIcon size={40} />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                Jira
              </h4>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-xs text-nowrap text-gray-500 dark:text-gray-300">
                  Create and manage security issues in Jira.
                </p>
                <CustomLink
                  href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-jira-integration/"
                  aria-label="Learn more about Jira integration"
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
              asLink="/integrations/jira"
              ariaLabel="Manage Jira integrations"
            >
              Manage
            </CustomButton>
          </div>
        </div>
      </CardHeader>
      <CardBody>
        <div className="flex flex-col gap-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Configure and manage your Jira integrations to automatically create
            issues for security findings in your Jira projects.
          </p>
        </div>
      </CardBody>
    </Card>
  );
};
