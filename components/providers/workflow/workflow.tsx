"use client";

import { Progress, Spacer } from "@nextui-org/react";
import { usePathname } from "next/navigation";
import React from "react";

import { VerticalSteps } from "./vertical-steps";

const steps = [
  {
    title: "Add your cloud account",
    description: "Please add your cloud account to get started.",
    href: "/providers/connect-account",
  },
  {
    title: "Add credentials to your cloud provider",
    description: "Please add your credentials to your cloud provider.",
    href: "/providers/add-credentials",
  },
  {
    title: "Test connection",
    description: "Please test your connection to your cloud provider.",
    href: "/providers/test-connection",
  },
  {
    title: "Lunch scan",
    description: "Please choose when you want to launch your scan.",
    href: "/providers",
  },
];

export const Workflow = () => {
  const pathname = usePathname();

  // Calculate current step based on pathname
  const currentStepIndex = steps.findIndex((step) =>
    pathname.endsWith(step.href),
  );
  const currentStep = currentStepIndex === -1 ? 0 : currentStepIndex;

  return (
    <section className="max-w-sm">
      <h1 className="mb-2 text-xl font-medium" id="getting-started">
        Getting started
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
        stepClassName="border border-default-200 dark:border-default-50 aria-[current]:bg-default-100 dark:aria-[current]:bg-default-50"
        steps={steps}
      />
      <Spacer y={4} />
    </section>
  );
};
