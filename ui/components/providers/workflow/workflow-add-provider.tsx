"use client";

import { Progress, Spacer } from "@nextui-org/react";
import { usePathname } from "next/navigation";
import React from "react";

import { VerticalSteps } from "./vertical-steps";

const steps = [
  {
    title: "Add your cloud provider",
    description:
      "Select the cloud provider for the account to connect and specify whether to use an IAM role or credentials for access.",
    href: "/providers/connect-account",
  },
  {
    title: "Add credentials to your cloud provider",
    description:
      "Provide the credentials required to connect to the cloud provider.",
    href: "/providers/add-credentials",
  },
  {
    title: "Check connection and launch scan",
    description:
      "Verify the connection to ensure that the provided credentials are valid for accessing the cloud provider and initiating a scan.",
    href: "/providers/test-connection",
  },
];

export const WorkflowAddProvider = () => {
  const pathname = usePathname();

  // Calculate current step based on pathname
  const currentStepIndex = steps.findIndex((step) =>
    pathname.endsWith(step.href),
  );
  const currentStep = currentStepIndex === -1 ? 0 : currentStepIndex;

  return (
    <section className="max-w-sm">
      <h1 className="mb-2 text-xl font-medium" id="getting-started">
        Add a cloud provider
      </h1>
      <p className="mb-5 text-small text-default-500">
        Complete the steps to configure the cloud provider, enabling the launch
        of the first scan once completed.
      </p>
      <Progress
        classNames={{
          base: "px-0.5 mb-5",
          label: "text-small",
          value: "text-small text-default-400",
        }}
        label="Steps"
        maxValue={steps.length - 1}
        minValue={0}
        showValueLabel={true}
        size="md"
        value={currentStep}
        valueLabel={`${currentStep + 1} of ${steps.length}`}
      />
      <VerticalSteps
        hideProgressBars
        currentStep={currentStep}
        stepClassName="border border-default-200 dark:border-default-50 aria-[current]:bg-default-100 dark:aria-[current]:bg-prowler-blue-800 cursor-default"
        steps={steps}
      />
      <Spacer y={4} />
    </section>
  );
};
