"use client";

import { GithubIcon, SettingsIcon } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn";
import { CustomLink } from "@/components/ui/custom/custom-link";

import { Card, CardContent, CardHeader } from "../../shadcn";

export const GitHubIntegrationCard = () => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <GithubIcon size={40} className="text-gray-900 dark:text-gray-100" />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                GitHub
              </h4>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-xs text-nowrap text-gray-500 dark:text-gray-300">
                  Create security issues in GitHub repositories.
                </p>
                <CustomLink
                  href="https://docs.prowler.com"
                  aria-label="Learn more about GitHub integration"
                  size="xs"
                >
                  Learn more
                </CustomLink>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href="/integrations/github">
                <SettingsIcon size={14} />
                Manage
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Configure and manage your GitHub integrations to automatically create
          issues for security findings in your GitHub repositories.
        </p>
      </CardContent>
    </Card>
  );
};
