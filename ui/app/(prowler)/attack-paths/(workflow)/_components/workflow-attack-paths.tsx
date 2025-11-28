"use client";

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

  const currentStep = isQueryBuilderStep ? 1 : 0; // 0-indexed

  const steps = [
    {
      title: "Select Attack Paths Scan",
      description: "Choose an AWS account and its latest Attack Paths scan",
    },
    {
      title: "Build Query & Visualize",
      description: "Create a query and view the Attack Paths graph",
    },
  ];

  const progressPercentage = (currentStep / (steps.length - 1)) * 100;

  return (
    <section className="flex flex-col gap-6">
      <div>
        <div className="bg-bg-neutral-tertiary mb-4 h-2 w-full overflow-hidden rounded-full">
          <div
            className="bg-success-primary h-full transition-all duration-300"
            style={{ width: `${progressPercentage}%` }}
          />
        </div>
        <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
          Step {currentStep + 1} of {steps.length}
        </h3>
      </div>

      <VerticalSteps currentStep={currentStep} steps={steps} color="success" />
    </section>
  );
};
