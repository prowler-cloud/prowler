"use client";

import { Card, CardBody, CardHeader, Skeleton } from "@nextui-org/react";

import { AWSSecurityHubIcon } from "@/components/icons/services/IconServices";

interface SecurityHubIntegrationCardSkeletonProps {
  variant?: "main" | "manager";
  count?: number;
}

export const SecurityHubIntegrationCardSkeleton = ({
  variant = "main",
  count = 1,
}: SecurityHubIntegrationCardSkeletonProps) => {
  if (variant === "main") {
    return (
      <Card className="dark:bg-prowler-blue-400">
        <CardHeader className="gap-2">
          <div className="flex w-full items-center justify-between">
            <div className="flex items-center gap-3">
              <AWSSecurityHubIcon size={40} />
              <div className="flex flex-col gap-1">
                <h4 className="text-lg font-bold">AWS Security Hub</h4>
                <div className="flex items-center gap-2">
                  <p className="text-xs text-gray-500">
                    Send security findings to AWS Security Hub.
                  </p>
                  <Skeleton className="h-4 w-20 rounded" />
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Skeleton className="h-8 w-24 rounded" />
            </div>
          </div>
        </CardHeader>
        <CardBody>
          <div className="flex flex-col gap-4">
            <Skeleton className="h-4 w-full rounded" />
            <Skeleton className="h-4 w-3/4 rounded" />
          </div>
        </CardBody>
      </Card>
    );
  }

  return (
    <div className="grid gap-4">
      {Array.from({ length: count }).map((_, index) => (
        <Card key={index} className="dark:bg-prowler-blue-400">
          <CardHeader className="pb-2">
            <div className="flex w-full items-center justify-between">
              <div className="flex items-center gap-3">
                <AWSSecurityHubIcon size={32} />
                <div className="flex flex-col gap-1">
                  <Skeleton className="h-5 w-40 rounded" />
                  <Skeleton className="h-3 w-32 rounded" />
                </div>
              </div>
              <Skeleton className="h-6 w-20 rounded-full" />
            </div>
          </CardHeader>
          <CardBody className="pt-0">
            <div className="flex flex-col gap-3">
              <div className="flex flex-wrap gap-1">
                <Skeleton className="h-6 w-16 rounded-full" />
                <Skeleton className="h-6 w-20 rounded-full" />
                <Skeleton className="w-18 h-6 rounded-full" />
              </div>
              <div className="flex items-center justify-between">
                <Skeleton className="h-3 w-32 rounded" />
                <div className="flex items-center gap-2">
                  <Skeleton className="h-7 w-16 rounded" />
                  <Skeleton className="h-7 w-20 rounded" />
                  <Skeleton className="h-7 w-24 rounded" />
                  <Skeleton className="h-7 w-20 rounded" />
                  <Skeleton className="h-7 w-20 rounded" />
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      ))}
    </div>
  );
};
