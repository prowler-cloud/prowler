"use client";

import { AlertCircle, FolderGit2, KeyRound, Shield } from "lucide-react";

import { ProwlerShort } from "@/components/icons/prowler/ProwlerIcons";
import { cn } from "@/lib/utils";
import { IconComponent, IconSvgProps } from "@/types/components";
import { OrgWizardStep } from "@/types/organizations";

interface OrgWizardStepperProps {
  currentStep: OrgWizardStep;
  hasConnectionErrors: boolean;
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
    icon: Shield,
  },
  {
    label: "Launch Scan",
    description: "Scan newly connected resources.",
    icon: ProwlerShort,
  },
];

/**
 * Maps modal internal step (0=Setup, 1=Validate, 2=Launch) to the
 * visual stepper index (0-3). Step 0 in the stepper is always complete.
 */
function getVisualStepIndex(modalStep: OrgWizardStep): number {
  return modalStep + 1;
}

export function OrgWizardStepper({
  currentStep,
  hasConnectionErrors,
}: OrgWizardStepperProps) {
  const activeVisualStep = getVisualStepIndex(currentStep);

  return (
    <nav aria-label="Wizard progress" className="flex flex-col gap-0">
      {STEPS.map((step, index) => {
        const isComplete = index < activeVisualStep;
        const isActive = index === activeVisualStep;
        const isInactive = index > activeVisualStep;
        const isErrorStep = index === 2 && hasConnectionErrors && isActive;

        return (
          <div key={step.label} className="flex items-start gap-3">
            {/* Step indicator + connector line */}
            <div className="flex flex-col items-center">
              <StepCircle
                isComplete={isComplete}
                isActive={isActive}
                isError={isErrorStep}
                icon={step.icon}
              />
              {/* Connector line */}
              {index < STEPS.length - 1 && (
                <div
                  className={cn(
                    "h-14 w-0 border-l border-dashed",
                    isComplete ? "border-primary/40" : "border-[#202020]",
                  )}
                />
              )}
            </div>

            {/* Label + description */}
            <div className="flex flex-col gap-1 pt-[10px]">
              <span
                className={cn(
                  "text-lg leading-7 font-normal",
                  isActive && "text-[#f4f4f5]",
                  isComplete && "text-[#f4f4f5]",
                  isInactive && "text-[#f4f4f5]/60",
                  isErrorStep && "text-destructive",
                )}
              >
                {step.label}
              </span>
              <p className="text-xs leading-5 text-[#d4d4d8]">
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
  isError: boolean;
  icon: IconComponent;
}

function StepCircle({
  isComplete,
  isActive,
  isError,
  icon: Icon,
}: StepCircleProps) {
  if (isError) {
    return (
      <div className="border-destructive flex size-[44px] shrink-0 items-center justify-center rounded-full border bg-[#121110]">
        <AlertCircle className="text-destructive size-6" />
      </div>
    );
  }

  const borderColor =
    isComplete || isActive ? "border-primary" : "border-[#202020]";
  const iconColor = isComplete || isActive ? "text-primary" : "text-[#525252]";

  return (
    <div
      className={cn(
        "flex size-[44px] shrink-0 items-center justify-center rounded-full border bg-[#121110]",
        borderColor,
      )}
    >
      <StepIcon icon={Icon} className={iconColor} />
    </div>
  );
}

/**
 * Renders either a Lucide icon (className-based) or a custom SVG icon
 * (size-prop-based like ProwlerShort) with consistent sizing.
 */
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

/**
 * Type guard: Lucide icons have a `displayName` property set by lucide-react.
 * Custom SVG icons (React.FC<IconSvgProps>) accept a `size` number prop.
 */
function isCustomSvgIcon(icon: IconComponent): icon is React.FC<IconSvgProps> {
  return !("displayName" in icon && typeof icon.displayName === "string");
}
