"use client";

import React from "react";

import { InfoIcon } from "../icons/Icons";
import { CustomButton } from "../ui/custom";

export const NoProvidersConnected = () => {
  return (
    <div className="flex items-center justify-start rounded-lg border-1 border-system-warning-light px-4 py-6 shadow-box dark:bg-prowler-blue-400">
      <div className="flex w-full flex-col items-start gap-6 md:flex-row md:items-center md:justify-between md:gap-8">
        <div className="flex flex-col space-y-3">
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
        <div className="w-full md:w-auto md:flex-shrink-0">
          <CustomButton
            asLink="/providers"
            className="w-full justify-center md:w-fit"
            ariaLabel="Go to Cloud providers page"
            variant="solid"
            color="action"
            size="md"
          >
            Review Cloud Providers
          </CustomButton>
        </div>
      </div>
    </div>
  );
};
