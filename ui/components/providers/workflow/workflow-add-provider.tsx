"use client";

import { Progress, Spacer } from "@nextui-org/react";
import { usePathname } from "next/navigation";
import React from "react";

import { VerticalSteps } from "./vertical-steps";

const steps = [
  {
    title: "Add your cloud account",
    description:
      "Select the cloud provider of the account you want to connect and choose whether to use IAM role or credentials for access.",
    href: "/providers/connect-account",
  },
  {
    title: "Add credentials to your cloud account",
    description: "Add the credentials needed to connect to your cloud account.",
    href: "/providers/add-credentials",
  },
  {
    title: "Test connection",
    description:
      "Test your connection to verify that the credentials provided are valid for accessing your cloud account.",
    href: "/providers/test-connection",
  },
  {
    title: "Success",
    description:
      "Your cloud account has been successfully connected and the scan has been launched.",
    href: "/providers/launch-scan",
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
        Add a cloud account
      </h1>
      <p className="mb-5 text-small text-default-500">
        Follow the steps to configure your cloud account. This allows you to
        launch the first scan when the process is complete.
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
