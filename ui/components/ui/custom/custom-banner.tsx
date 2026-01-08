"use client";

import { InfoIcon } from "lucide-react";
import Link from "next/link";

import { Button, Card, CardContent } from "@/components/shadcn";

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
    <Card variant="inner">
      <CardContent className="flex items-center justify-start">
        <div className="flex w-full flex-col items-start gap-6 md:flex-row md:items-center md:justify-between md:gap-8">
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-start gap-3">
              <InfoIcon className="text-bg-data-info h-6 w-6" />
              <h2 className="text-lg font-bold text-gray-800 dark:text-white">
                {title}
              </h2>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-300">
              {message}
            </p>
          </div>
          <div className="w-full md:w-auto md:shrink-0">
            <Button
              asChild
              className="w-full justify-center md:w-fit"
              size="default"
            >
              <Link href={buttonLink}>{buttonLabel}</Link>
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
