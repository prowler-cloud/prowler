"use client";

import { InfoIcon } from "lucide-react";

import { CustomButton } from ".";

interface CustomBannerProps {
  title: string;
  message: string;
  buttonLabel?: string;
  buttonLink?: string;
}

export const CustomBanner = ({
  title,
  message,
  buttonLabel = "Go Home",
  buttonLink = "/",
}: CustomBannerProps) => {
  return (
    <div className="border-system-warning-light shadow-box dark:bg-prowler-blue-400 flex items-center justify-start rounded-lg border px-4 py-6">
      <div className="flex w-full flex-col items-start gap-6 md:flex-row md:items-center md:justify-between md:gap-8">
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-start gap-3">
            <InfoIcon className="h-6 w-6 text-gray-800 dark:text-white" />
            <h2 className="text-lg font-bold text-gray-800 dark:text-white">
              {title}
            </h2>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-300">{message}</p>
        </div>
        <div className="w-full md:w-auto md:shrink-0">
          <CustomButton
            asLink={buttonLink}
            className="w-full justify-center md:w-fit"
            ariaLabel={buttonLabel}
            variant="solid"
            color="action"
            size="md"
          >
            {buttonLabel}
          </CustomButton>
        </div>
      </div>
    </div>
  );
};
