"use client";

import { Card, CardBody } from "@nextui-org/react";
import React from "react";

import { InfoIcon } from "../icons/Icons";
import { CustomButton } from "../ui/custom";

export const NoProvidersAdded = () => {
  return (
    <div className="flex min-h-screen items-center justify-center dark:bg-prowler-blue-800">
      <div className="mx-auto w-full max-w-7xl px-4">
        <Card className="mx-auto w-full max-w-3xl rounded-lg dark:bg-prowler-blue-400">
          <CardBody className="flex flex-col items-center space-y-4 p-6 text-center sm:p-8">
            <div className="flex flex-col items-center space-y-4">
              <InfoIcon className="h-10 w-10 text-gray-800 dark:text-white" />
              <h2 className="text-2xl font-bold text-gray-800 dark:text-white">
                No Cloud Providers Configured
              </h2>
            </div>
            <div className="flex flex-col items-center space-y-3">
              <p className="text-md leading-relaxed text-gray-600 dark:text-gray-300">
                No cloud providers have been configured. Start by setting up a
                cloud provider.
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
