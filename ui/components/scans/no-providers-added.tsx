"use client";

import Link from "next/link";

import { Button, Card, CardContent } from "@/components/shadcn";

import { InfoIcon } from "../icons/Icons";

export const NoProvidersAdded = () => {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Card variant="base" className="mx-auto w-full max-w-3xl">
        <CardContent className="flex flex-col items-center gap-4 p-6 text-center sm:p-8">
          <div className="flex flex-col items-center gap-4">
            <InfoIcon className="h-10 w-10 text-gray-800 dark:text-white" />
            <h2 className="text-2xl font-bold text-gray-800 dark:text-white">
              No Cloud Providers Configured
            </h2>
          </div>
          <div className="flex flex-col items-center gap-3">
            <p className="text-md leading-relaxed text-gray-600 dark:text-gray-300">
              No cloud providers have been configured. Start by setting up a
              cloud provider.
            </p>
          </div>

          <Button
            asChild
            aria-label="Go to Add Cloud Provider page"
            className="w-full max-w-xs justify-center"
            size="lg"
          >
            <Link href="/providers/connect-account">Get Started</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};
