"use client";

import { Progress, Spacer } from "@nextui-org/react";
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

const stepOverrides: Record<
  string,
  { index: number; title: string; description: string }
> = {
  "/providers/update-credentials": {
    index: 2,
    title: "Make sure the new credentials are valid",
    description: "Valid credentials will take you back to the providers page",
  },
};

const baseRouteToStepMap = Object.fromEntries(
  steps.map((step, index) => [step.href, index]),
);

const routeToStepIndexMap: Record<string, number> = {
  ...baseRouteToStepMap,
  "/providers/update-credentials":
    baseRouteToStepMap["/providers/add-credentials"],
};

export const WorkflowAddProvider = () => {
  const pathname = usePathname();

  const updatedSteps = steps.map((step, index) => {
    const override = stepOverrides[pathname];
    if (override && index === override.index) {
      return {
        ...step,
        title: override.title,
        description: override.description,
      };
    }
    return step;
  });
  const currentStep = routeToStepIndexMap[pathname] ?? 0;

  return (
    <section className="max-w-sm">
      <h1 className="mb-2 text-xl font-medium" id="getting-started">
        Add a Cloud Provider
      </h1>
      <p className="mb-5 text-small text-default-500">
        Complete these steps to configure your cloud provider and initiate your
        first scan.
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
        steps={updatedSteps}
      />
      <Spacer y={4} />
    </section>
  );
};
