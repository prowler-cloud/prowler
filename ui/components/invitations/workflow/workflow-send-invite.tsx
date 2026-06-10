"use client";

import { usePathname } from "next/navigation";
import React from "react";

import { Progress } from "@/components/shadcn/progress";

import { VerticalSteps } from "./vertical-steps";

const steps = [
  {
    title: "Send Invitation",
    description:
      "Enter the email address of the person you want to invite and send the invitation.",
    href: "/invitations/new",
  },
  {
    title: "Review Invitation Details",
    description:
      "Review the invitation details and share the information required for the person to accept the invitation.",
    href: "/invitations/check-details",
  },
];

export const WorkflowSendInvite = () => {
  const pathname = usePathname();

  // Calculate current step based on pathname
  const currentStepIndex = steps.findIndex((step) =>
    pathname.endsWith(step.href),
  );
  const currentStep = currentStepIndex === -1 ? 0 : currentStepIndex;

  return (
    <section className="w-full max-w-none p-3 sm:max-w-sm sm:p-0">
      <h1 className="mb-2 text-lg font-medium sm:text-xl" id="getting-started">
        Send invitation
      </h1>
      <p className="text-text-neutral-tertiary mb-3 text-xs sm:mb-5 sm:text-sm">
        Follow the steps to send an invitation to the users.
      </p>
      <div className="mb-3 flex flex-col gap-2 px-0.5 sm:mb-5">
        <div className="flex items-center justify-between">
          <span className="text-xs sm:text-sm">Steps</span>
          <span className="text-text-neutral-tertiary text-xs sm:text-sm">
            {`${currentStep + 1} of ${steps.length}`}
          </span>
        </div>
        <Progress
          aria-label="Steps"
          value={((currentStep + 1) / steps.length) * 100}
          className="h-1"
          indicatorClassName="bg-button-primary"
        />
      </div>

      {/* Desktop: Full vertical steps */}
      <div className="hidden sm:block">
        <VerticalSteps
          hideProgressBars
          currentStep={currentStep}
          stepClassName="border border-border-neutral-primary aria-[current]:border-button-primary aria-[current]:text-text-neutral-primary cursor-default"
          steps={steps}
        />
      </div>

      {/* Mobile: Compact current step indicator */}
      <div className="sm:hidden">
        <div className="text-text-neutral-secondary border-button-primary border-l-2 py-1 pl-3 text-xs">
          <div className="font-medium">
            Current: {steps[currentStep]?.title}
          </div>
          <div className="text-text-neutral-tertiary mt-1 text-xs">
            {steps[currentStep]?.description}
          </div>
        </div>
      </div>

      <div className="h-2" />
    </section>
  );
};
