"use client";

import { Progress } from "@heroui/progress";
import { usePathname } from "next/navigation";

import { VerticalSteps } from "./vertical-steps";

/**
 * Workflow steps component for Attack Paths wizard
 * Shows progress and navigation steps for the two-step process
 */
export const WorkflowAttackPaths = () => {
  const pathname = usePathname();

  // Determine current step based on pathname
  const isQueryBuilderStep = pathname.includes("query-builder");

  const currentStep = isQueryBuilderStep ? 1 : 0; // 0-indexed for Progress

  const steps = [
    {
      title: "Select Attack Path Scan",
      description: "Choose an AWS account and its latest attack path scan",
    },
    {
      title: "Build Query & Visualize",
      description: "Create a query and view the attack path graph",
    },
  ];

  return (
    <section className="flex flex-col gap-6">
      <div>
        <Progress
          value={currentStep}
          maxValue={steps.length - 1}
          color="success"
          className="mb-4"
        />
        <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
          Step {currentStep + 1} of {steps.length}
        </h3>
      </div>

      <VerticalSteps currentStep={currentStep} steps={steps} color="success" />
    </section>
  );
};
