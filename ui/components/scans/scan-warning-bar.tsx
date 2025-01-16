"use client";

import { InfoIcon } from "../icons";

export const ScanWarningBar = () => {
  return (
    <div className="flex items-center rounded-lg border border-system-warning bg-system-warning-medium p-4 text-sm dark:text-default-300">
      <InfoIcon className="mr-4 inline h-4 w-4 flex-shrink-0" />
      <div className="flex flex-col gap-1">
        <strong>Waiting for Your Scan to Show Up?</strong>
        <p>
          It may take a few minutes for the scan to appear on the table and be
          displayed.
        </p>
      </div>
    </div>
  );
};
