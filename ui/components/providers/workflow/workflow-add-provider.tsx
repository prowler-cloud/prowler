"use client";

import { Progress } from "@heroui/progress";
import { Spacer } from "@heroui/spacer";
import { usePathname } from "next/navigation";
import React from "react";

import { VerticalSteps } from "./vertical-steps";

const steps = [
  {
    title: "Choose your Cloud Provider",
    description:
      "Select the cloud provider you wish to connect and specify your preferred authentication method from the supported options.",
    href: "/providers/connect-account",
  },
  {
    title: "Enter Authentication Details",
    description:
      "Provide the necessary credentials to establish a secure connection to your selected cloud provider.",
    href: "/providers/add-credentials",
  },
  {
    title: "Verify Connection & Start Scan",
    description:
      "Ensure your credentials are correct and start scanning your cloud environment.",
    href: "/providers/test-connection",
  },
];

const ROUTE_CONFIG: Record<
  string,
  {
    stepIndex: number;
    stepOverride?: { index: number; title: string; description: string };
  }
> = {
  "/providers/connect-account": { stepIndex: 0 },
  "/providers/add-credentials": { stepIndex: 1 },
  "/providers/test-connection": { stepIndex: 2 },
  "/providers/update-credentials": {
    stepIndex: 1,
    stepOverride: {
      index: 2,
      title: "Make sure the new credentials are valid",
      description: "Valid credentials will take you back to the providers page",
    },
  },
};

export const WorkflowAddProvider = () => {
  const pathname = usePathname();

  const config = ROUTE_CONFIG[pathname] || { stepIndex: 0 };
  const currentStep = config.stepIndex;

  const updatedSteps = steps.map((step, index) => {
    if (config.stepOverride && index === config.stepOverride.index) {
      return { ...step, ...config.stepOverride };
    }
    return step;
  });

  return (
    <section className="max-w-sm">
      <h1 className="mb-2 text-xl font-medium" id="getting-started">
        Add a Cloud Provider
      </h1>
      <p className="text-small text-default-500 mb-5">
        Complete these steps to configure your cloud provider and initiate your
        first scan.
      </p>
      <Progress
        classNames={{
          base: "px-0.5 mb-5",
          label: "text-small",
          value: "text-small text-button-primary",
          indicator: "bg-button-primary",
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
        stepClassName="border border-border-neutral-primary aria-[current]:border-button-primary aria-[current]:text-text-neutral-primary cursor-default"
        steps={updatedSteps}
      />
      <Spacer y={4} />
    </section>
  );
};
