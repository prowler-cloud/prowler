"use client";

import { Icon } from "@iconify/react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";

export const ComplianceWarming = () => {
  const router = useRouter();

  return (
    <div className="flex h-full min-h-[calc(100vh-56px)] items-center justify-center">
      <div className="mx-auto w-full max-w-2xl">
        <Card variant="base" padding="lg">
          <CardContent>
            <div className="flex w-full items-center justify-between gap-6">
              <div className="flex items-start gap-4">
                <Icon
                  icon="tabler:clock"
                  className="mt-1 h-5 w-5 text-gray-400 dark:text-gray-300"
                />
                <div>
                  <h2 className="mb-1 text-base font-medium text-gray-900 dark:text-white">
                    Compliance data is still loading
                  </h2>
                  <p className="text-sm text-gray-500 dark:text-gray-300">
                    This can happen for a few seconds right after an update.
                    Please try again shortly.
                  </p>
                </div>
              </div>
              <Button
                variant="secondary"
                size="sm"
                className="shrink-0 gap-2"
                onClick={() => router.refresh()}
                aria-label="Reload compliance data"
              >
                <Icon icon="tabler:refresh" className="h-4 w-4" />
                Try Again
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
