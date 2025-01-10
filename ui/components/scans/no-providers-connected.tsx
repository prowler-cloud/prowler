"use client";

import { Card, CardBody } from "@nextui-org/react";
import React from "react";

import { CustomButton } from "../ui/custom";

export const NoProvidersConnected = () => {
  return (
    <div className="flex items-center justify-center">
      <Card shadow="sm" className="w-full max-w-md dark:bg-prowler-blue-400">
        <CardBody className="space-y-6 p-6 text-center">
          <h2 className="text-xl font-bold">No Cloud Accounts Connected</h2>
          <p className="text-md text-gray-600">
            All your cloud accounts are currently disconnected. Please review
            their configuration to proceed.
          </p>
          <CustomButton
            asLink="/providers"
            ariaLabel="Go to Cloud accounts page"
            variant="solid"
            color="action"
            size="lg"
          >
            Review Cloud Accounts
          </CustomButton>
        </CardBody>
      </Card>
    </div>
  );
};
