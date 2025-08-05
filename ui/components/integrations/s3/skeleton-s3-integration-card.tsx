"use client";

import { Card, CardBody, CardHeader, Skeleton } from "@nextui-org/react";

import { AmazonS3Icon } from "@/components/icons/services/IconServices";

interface S3IntegrationCardSkeletonProps {
  variant?: "main" | "manager";
  count?: number;
}

export const S3IntegrationCardSkeleton = ({
  variant = "main",
  count = 1,
}: S3IntegrationCardSkeletonProps) => {
  if (variant === "main") {
    return (
      <Card className="dark:bg-prowler-blue-400">
        <CardHeader className="gap-2">
          <div className="flex w-full items-center justify-between">
            <div className="flex items-center gap-3">
              <AmazonS3Icon size={40} />
              <div className="flex flex-col gap-1">
                <h4 className="text-lg font-bold">Amazon S3</h4>
                <div className="flex items-center gap-2">
                  <p className="text-xs text-gray-500">
                    Export security findings to Amazon S3 buckets.
                  </p>
                  <Skeleton className="h-3 w-16 rounded" />
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Skeleton className="h-6 w-20 rounded-full" />
              <Skeleton className="h-8 w-20 rounded-lg" />
            </div>
          </div>
        </CardHeader>
        <CardBody>
          <div className="flex flex-col gap-4">
            <div className="space-y-2">
              {Array.from({ length: count }).map((_, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between rounded-lg border p-3"
                >
                  <div className="flex flex-col gap-1">
                    <Skeleton className="h-4 w-32 rounded" />
                    <Skeleton className="h-3 w-48 rounded" />
                  </div>
                  <Skeleton className="h-6 w-20 rounded-full" />
                </div>
              ))}
            </div>
          </div>
        </CardBody>
      </Card>
    );
  }

  // Manager variant - for individual cards in S3IntegrationsManager
  return (
    <div className="grid gap-4">
      {Array.from({ length: count }).map((_, index) => (
        <Card key={index} className="dark:bg-prowler-blue-400">
          <CardHeader className="pb-2">
            <div className="flex w-full items-center justify-between">
              <div className="flex items-center gap-3">
                <AmazonS3Icon size={32} />
                <div className="flex flex-col gap-1">
                  <Skeleton className="h-5 w-40 rounded" />
                  <Skeleton className="h-3 w-32 rounded" />
                </div>
              </div>
              <Skeleton className="h-6 w-20 rounded-full" />
            </div>
          </CardHeader>
          <CardBody className="pt-0">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Skeleton className="h-3 w-48 rounded" />
                <Skeleton className="h-3 w-36 rounded" />
              </div>
              <div className="flex items-center gap-2">
                <Skeleton className="h-8 w-16 rounded" />
                <Skeleton className="h-8 w-16 rounded" />
                <Skeleton className="h-8 w-20 rounded" />
              </div>
            </div>
          </CardBody>
        </Card>
      ))}
    </div>
  );
};
