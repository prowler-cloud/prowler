"use client";
import { Card, CardBody } from "@nextui-org/react";
import React from "react";

import { CustomButton } from "../ui/custom";

export const NoProvidersAdded = () => {
  return (
    <div className="flex h-screen items-center justify-center">
      <Card shadow="sm" className="w-full max-w-md dark:bg-prowler-blue-400">
        <CardBody className="space-y-6 p-6 text-center">
          <h2 className="text-xl font-bold">No Cloud Accounts Configured</h2>
          <p className="text-md text-gray-600">
            You don't have any cloud accounts configured yet. This is the first
            step to get started.
          </p>
          <CustomButton
            asLink="/providers/connect-account"
            ariaLabel="Go to Add Cloud Account page"
            variant="solid"
            color="action"
            size="lg"
          >
            Add Cloud Account
          </CustomButton>
        </CardBody>
      </Card>
    </div>
  );
};
