"use client";

import { usePathname } from "next/navigation";
import React from "react";

import { Progress } from "@/components/shadcn/progress";

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
      <div className="mb-5 flex flex-col gap-2 px-0.5">
        <div className="flex items-center justify-between">
          <span className="text-small">Steps</span>
          <span className="text-small text-default-400">
            {`${currentStep + 1} of ${steps.length}`}
          </span>
        </div>
        <Progress
          aria-label="Steps"
          value={(currentStep / (steps.length - 1)) * 100}
        />
      </div>
      <VerticalSteps
        hideProgressBars
        currentStep={currentStep}
        stepClassName="border border-border-neutral-primary aria-[current]:border-button-primary aria-[current]:text-text-neutral-primary cursor-default"
        steps={steps}
      />
      <div className="h-4" />
    </section>
  );
};
