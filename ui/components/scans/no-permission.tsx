"use client";

import { InfoIcon } from "lucide-react";

import { CustomButton } from "../ui/custom";

export const NoPermission = () => {
  return (
    <div className="flex items-center justify-start rounded-lg border-1 border-system-warning-light px-4 py-6 shadow-box dark:bg-prowler-blue-400">
      <div className="flex w-full flex-col items-start gap-6 md:flex-row md:items-center md:justify-between md:gap-8">
        <div className="flex flex-col space-y-3">
          <div className="flex items-center justify-start gap-3">
            <InfoIcon className="h-6 w-6 text-gray-800 dark:text-white" />
            <h2 className="text-lg font-bold text-gray-800 dark:text-white">
              Access Denied
            </h2>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            You don’t have permission to launch the scan.
          </p>
        </div>
        <div className="w-full md:w-auto md:flex-shrink-0">
          <CustomButton
            asLink="/"
            className="w-full justify-center md:w-fit"
            ariaLabel="Go back to Home"
            variant="solid"
            color="action"
            size="md"
          >
            Go Home
          </CustomButton>
        </div>
      </div>
    </div>
  );
};
