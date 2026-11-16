"use client";

import { SettingsIcon } from "lucide-react";
import Link from "next/link";

import { AmazonS3Icon } from "@/components/icons/services/IconServices";
import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { isCloud } from "@/lib/shared/env";

export const S3IntegrationCard = () => {
  // Adding S3 integrations needs Prowler Cloud; existing ones stay manageable.
  const isCloudOnly = !isCloud();

  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <AmazonS3Icon size={40} />
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2">
                <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                  Amazon S3
                </h4>
                {isCloudOnly && (
                  <Badge variant="cloud" size="sm">
                    Cloud
                  </Badge>
                )}
              </div>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-xs text-nowrap text-gray-500 dark:text-gray-300">
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
            <Button asChild size="sm">
              <Link href="/integrations/amazon-s3">
                <SettingsIcon size={14} />
                Manage
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Configure and manage your Amazon S3 integrations to automatically
          export security findings to your S3 buckets.
        </p>
      </CardContent>
    </Card>
  );
};
