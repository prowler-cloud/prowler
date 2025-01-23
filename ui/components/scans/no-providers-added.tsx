"use client";

import { Card, CardBody } from "@nextui-org/react";
import React from "react";

import { InfoIcon } from "../icons/Icons";
import { CustomButton } from "../ui/custom";

export const NoProvidersAdded = () => {
  return (
    <div className="dark:bg-prowler-blue-900 flex min-h-screen items-center justify-center">
      <div className="mx-auto w-full max-w-7xl px-4">
        <Card className="mx-auto w-full max-w-3xl rounded-lg dark:bg-prowler-blue-400">
          <CardBody className="flex flex-col items-center space-y-8 p-6 text-center sm:p-8">
            <div className="flex flex-col items-center space-y-4">
              <InfoIcon className="h-10 w-10 text-gray-800 dark:text-white" />
              <h2 className="text-2xl font-bold text-gray-800 dark:text-white">
                No Cloud Providers Configured
              </h2>
            </div>
            <div className="flex flex-col items-center space-y-3">
              <p className="text-md leading-relaxed text-gray-600 dark:text-gray-300">
                You don&apos;t have any cloud providers configured yet.
              </p>
              <p className="text-md leading-relaxed text-gray-600 dark:text-gray-300">
                Adding a cloud provider is the first step.
              </p>
            </div>
            <CustomButton
              asLink="/providers/connect-account"
              ariaLabel="Go to Add Cloud Provider page"
              className="w-full max-w-xs justify-center"
              variant="solid"
              color="action"
              size="lg"
            >
              Get Started
            </CustomButton>
          </CardBody>
        </Card>
      </div>
    </div>
  );
};
