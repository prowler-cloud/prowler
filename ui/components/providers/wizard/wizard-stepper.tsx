"use client";

import { CircleCheckBig, FolderGit2, KeyRound, Rocket } from "lucide-react";
import { ReactElement } from "react";

import { ProwlerShort } from "@/components/icons/prowler/ProwlerIcons";
import { cn } from "@/lib/utils";
import { IconComponent, IconSvgProps } from "@/types/components";

interface WizardStepperProps {
  currentStep: number;
  stepOffset?: number;
}

interface StepConfig {
  label: string;
  description: string;
  icon: IconComponent;
}

const STEPS: StepConfig[] = [
  {
    label: "Link a Cloud Provider",
    description: "Enter the provider details you would like to add in Prowler.",
    icon: FolderGit2,
  },
  {
    label: "Authenticate Credentials",
    description:
      "Authorize a secure connection between Prowler and your provider.",
    icon: KeyRound,
  },
  {
    label: "Validate Connection",
    description:
      "Review provider resources and test the connection to Prowler.",
    icon: Rocket,
  },
  {
    label: "Launch Scan",
    description: "Scan newly connected resources.",
    icon: ProwlerShort,
  },
];

export function WizardStepper({
  currentStep,
  stepOffset = 0,
}: WizardStepperProps) {
  const activeVisualStep = Math.max(
    0,
    Math.min(currentStep + stepOffset, STEPS.length - 1),
  );

  return (
    <nav aria-label="Wizard progress" className="flex flex-col gap-0">
      {STEPS.map((step, index) => {
        const isComplete = index < activeVisualStep;
        const isActive = index === activeVisualStep;
        const isInactive = index > activeVisualStep;

        return (
          <div key={step.label} className="flex items-start gap-3">
            <div className="flex flex-col items-center">
              <StepCircle
                isComplete={isComplete}
                isActive={isActive}
                icon={step.icon}
              />
              {index < STEPS.length - 1 && (
                <StepConnector isComplete={isComplete} />
              )}
            </div>

            <div className="flex flex-col gap-1 pt-[10px]">
              <span
                className={cn(
                  "text-lg leading-7 font-normal",
                  isActive && "text-text-neutral-primary",
                  isComplete && "text-text-neutral-primary",
                  isInactive && "text-text-neutral-tertiary",
                )}
              >
                {step.label}
              </span>
              <p className="text-text-neutral-secondary text-xs leading-5">
                {step.description}
              </p>
            </div>
          </div>
        );
      })}
    </nav>
  );
}

interface StepCircleProps {
  isComplete: boolean;
  isActive: boolean;
  icon: IconComponent;
}

function StepCircle({ isComplete, isActive, icon: Icon }: StepCircleProps) {
  if (isComplete) {
    return (
      <div className="bg-button-primary-press flex size-[44px] shrink-0 items-center justify-center rounded-full">
        <CircleCheckBig className="text-bg-neutral-primary size-6" />
      </div>
    );
  }

  if (isActive) {
    return (
      <div className="border-border-input-primary-pressed bg-bg-neutral-secondary flex size-[44px] shrink-0 items-center justify-center rounded-full border">
        <StepIcon icon={Icon} className="text-border-input-primary-pressed" />
      </div>
    );
  }

  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex size-[44px] shrink-0 items-center justify-center rounded-full border">
      <StepIcon icon={Icon} className="text-text-neutral-tertiary" />
    </div>
  );
}

function StepConnector({ isComplete }: { isComplete: boolean }) {
  if (isComplete) {
    return <div className="bg-border-input-primary-pressed h-14 w-px" />;
  }

  return (
    <div
      className="h-14 w-px"
      style={{
        backgroundImage:
          "repeating-linear-gradient(to bottom, var(--color-bg-data-muted) 0px, var(--color-bg-data-muted) 4px, transparent 4px, transparent 8px)",
      }}
    />
  );
}

function StepIcon({
  icon: Icon,
  className,
}: {
  icon: IconComponent;
  className: string;
}) {
  if (isCustomSvgIcon(Icon)) {
    return <Icon size={24} className={className} />;
  }
  return <Icon className={cn("size-6", className)} />;
}

function isCustomSvgIcon(
  icon: IconComponent,
): icon is (props: IconSvgProps) => ReactElement {
  return !("displayName" in icon && typeof icon.displayName === "string");
}
