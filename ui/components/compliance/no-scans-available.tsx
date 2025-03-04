"use client";

import React from "react";
import { InfoIcon } from "../icons/Icons";
import { CustomButton } from "../ui/custom";

export const NoScansAvailable = () => {
  return (
    <div className="flex h-full min-h-[calc(100vh-56px)] items-center justify-center">
      <div className="mx-auto w-full max-w-2xl">
        <div className="flex items-center justify-start rounded-lg border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-prowler-blue-400">
          <div className="flex w-full items-center justify-between gap-6">
            <div className="flex items-start gap-4">
              <InfoIcon className="mt-1 h-5 w-5 text-gray-400 dark:text-gray-300" />
              <div>
                <h2 className="mb-1 text-base font-medium text-gray-900 dark:text-white">
                  No Scans available
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-300">
                  A scan must be completed before generating a compliance
                  report.
                </p>
              </div>
            </div>
            <CustomButton
              asLink="/scans"
              className="flex-shrink-0"
              ariaLabel="Go to Scans page"
              variant="solid"
              color="action"
              size="sm"
            >
              Go to Scans
            </CustomButton>
          </div>
        </div>
      </div>
    </div>
  );
};
