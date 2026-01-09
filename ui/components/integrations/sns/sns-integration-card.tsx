"use client";

import { MailIcon, SettingsIcon } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn";
import { CustomLink } from "@/components/ui/custom/custom-link";

import { Card, CardContent, CardHeader } from "../../shadcn";

export const SNSIntegrationCard = () => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-orange-100 dark:bg-orange-900/30">
              <MailIcon
                size={24}
                className="text-orange-600 dark:text-orange-400"
              />
            </div>
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                Amazon SNS
              </h4>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-nowrap text-xs text-gray-500 dark:text-gray-300">
                  Send email alerts for security findings via SNS.
                </p>
                <CustomLink
                  href="https://docs.aws.amazon.com/sns/latest/dg/welcome.html"
                  aria-label="Learn more about Amazon SNS integration"
                  size="xs"
                  isExternal
                >
                  Learn more
                </CustomLink>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href="/integrations/sns">
                <SettingsIcon size={14} />
                Manage
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Configure Amazon SNS topics to send formatted email alerts for
          security findings with support for filtering by severity, provider,
          region, and resource tags.
        </p>
      </CardContent>
    </Card>
  );
};
