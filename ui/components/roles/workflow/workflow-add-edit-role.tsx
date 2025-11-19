"use client";

import { Progress } from "@heroui/progress";
import { Spacer } from "@heroui/spacer";
import { usePathname } from "next/navigation";
import React from "react";

import { VerticalSteps } from "./vertical-steps";

const steps = [
  {
    title: "Create a new role",
    description: "Enter the name of the role you want to add.",
    href: "/roles/new",
  },
  {
    title: "Edit a existing role",
    description:
      "Update the role's details, including its name and permissions.",
    href: "/roles/edit",
  },
];

export const WorkflowAddEditRole = () => {
  const pathname = usePathname();

  // Calculate current step based on pathname
  const currentStepIndex = steps.findIndex((step) =>
    pathname.endsWith(step.href),
  );
  const currentStep = currentStepIndex === -1 ? 0 : currentStepIndex;

  return (
    <section className="max-w-sm">
      <h1 className="mb-2 text-xl font-medium" id="getting-started">
        Manage Role Permissions
      </h1>
      <p className="text-small text-default-500 mb-5">
        Define a new role with customized permissions or modify an existing one
        to meet your needs.
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
        stepClassName="border border-border-neutral-primary aria-[current]:border-button-primary aria-[current]:text-text-neutral-primary cursor-default"
        steps={steps}
      />
      <Spacer y={4} />
    </section>
  );
};
