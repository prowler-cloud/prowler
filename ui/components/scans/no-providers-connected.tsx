"use client";

import Link from "next/link";

import { Button, Card, CardContent } from "@/components/shadcn";

import { InfoIcon } from "../icons/Icons";

export const NoProvidersConnected = () => {
  return (
    <Card variant="base">
      <CardContent className="flex w-full flex-col items-start gap-6 md:flex-row md:items-center md:justify-between md:gap-8">
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-start gap-3">
            <InfoIcon className="h-6 w-6 text-gray-800 dark:text-white" />
            <h2 className="text-lg font-bold text-gray-800 dark:text-white">
              No Connected Cloud Providers
            </h2>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            No cloud providers are currently connected. Connecting a cloud
            provider is required to launch on-demand scans.
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Once the cloud providers are correctly configured, this message will
            disappear, and on-demand scans can be launched.
          </p>
        </div>
        <div className="w-full md:w-auto md:shrink-0">
          <Button
            asChild
            className="w-full justify-center md:w-fit"
            aria-label="Go to Cloud providers page"
          >
            <Link href="/providers">Review Cloud Providers</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};
