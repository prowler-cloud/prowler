"use client";

import Link from "next/link";
import React from "react";

import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";

import { InfoIcon } from "../icons/Icons";

export const NoScansAvailable = () => {
  return (
    <div className="flex h-full min-h-[calc(100vh-56px)] items-center justify-center">
      <div className="mx-auto w-full max-w-2xl">
        <Card variant="base" padding="lg">
          <CardContent>
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
              <Button
                asChild
                variant="secondary"
                size="sm"
                className="shrink-0"
              >
                <Link href="/scans" aria-label="Go to Scans page">
                  Go to Scans
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
