"use client";

import { CircleCheckBig, FolderGit2, KeyRound, Rocket } from "lucide-react";
import { Fragment, ReactElement } from "react";

import { ProwlerShort } from "@/components/icons/prowler/ProwlerIcons";
import { cn } from "@/lib/utils";
import { IconComponent, IconSvgProps } from "@/types/components";

interface StepConfig {
  label: string;
  description: string;
  icon: IconComponent;
}

interface WizardStepperProps {
  currentStep: number;
  stepOffset?: number;
  steps?: StepConfig[];
}

const STEPS: StepConfig[] = [
  {
    label: "Link a Provider",
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

export const PROVIDER_WIZARD_STEPS = STEPS;

// AWS registers the account, stores its credentials and tests the connection in
// one step, so the wizard goes straight from CONNECT to LAUNCH.
export const AWS_PROVIDER_WIZARD_STEPS: StepConfig[] = [
  {
    label: "Link a Provider",
    description:
      "Enter the account details and the credentials Prowler will use, then test the connection.",
    icon: FolderGit2,
  },
  STEPS[3],
];

/** The stepper row a wizard step lands on once its offset is applied. */
export function getActiveStepIndex(
  currentStep: number,
  stepOffset: number,
  stepCount: number,
): number {
  return Math.max(0, Math.min(currentStep + stepOffset, stepCount - 1));
}

const CONNECTOR_DIRECTION = {
  VERTICAL: "to bottom",
  HORIZONTAL: "to right",
} as const;
type ConnectorDirection =
  (typeof CONNECTOR_DIRECTION)[keyof typeof CONNECTOR_DIRECTION];

export function WizardStepper({
  currentStep,
  stepOffset = 0,
  steps = STEPS,
}: WizardStepperProps) {
  const activeVisualStep = getActiveStepIndex(
    currentStep,
    stepOffset,
    steps.length,
  );

  // Below lg the wizard stacks: one row of steps, naming only the current one.
  return (
    <nav
      aria-label="Wizard progress"
      className="flex items-center gap-2 lg:flex-col lg:items-stretch lg:gap-0"
    >
      {steps.map((step, index) => {
        const isComplete = index < activeVisualStep;
        const isActive = index === activeVisualStep;
        const isInactive = index > activeVisualStep;
        const hasNext = index < steps.length - 1;

        return (
          <Fragment key={step.label}>
            <div
              aria-current={isActive ? "step" : undefined}
              className={cn(
                "flex min-w-0 items-center gap-2 lg:items-start lg:gap-3",
                !isActive && "shrink-0",
              )}
            >
              <div className="flex flex-col items-center">
                <StepCircle
                  isComplete={isComplete}
                  isActive={isActive}
                  icon={step.icon}
                />
                {hasNext && (
                  <StepConnector
                    isComplete={isComplete}
                    className="hidden h-14 w-px lg:block"
                    direction={CONNECTOR_DIRECTION.VERTICAL}
                  />
                )}
              </div>

              <div
                className={cn(
                  "min-w-0 flex-col gap-1 lg:flex lg:pt-[10px]",
                  isActive ? "flex" : "hidden",
                )}
              >
                <span
                  className={cn(
                    "truncate text-sm font-normal lg:overflow-visible lg:text-lg lg:leading-7 lg:whitespace-normal",
                    isActive && "text-text-neutral-primary",
                    isComplete && "text-text-neutral-primary",
                    isInactive && "text-text-neutral-tertiary",
                  )}
                >
                  {step.label}
                </span>
                <p className="text-text-neutral-secondary hidden text-xs leading-5 lg:block">
                  {step.description}
                </p>
              </div>
            </div>
            {hasNext && (
              <StepConnector
                isComplete={isComplete}
                className="h-px min-w-3 flex-1 lg:hidden"
                direction={CONNECTOR_DIRECTION.HORIZONTAL}
              />
            )}
          </Fragment>
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

const CIRCLE_SIZE = "size-8 lg:size-[44px]";

function StepCircle({ isComplete, isActive, icon: Icon }: StepCircleProps) {
  if (isComplete) {
    return (
      <div
        className={cn(
          "bg-button-primary-press flex shrink-0 items-center justify-center rounded-full",
          CIRCLE_SIZE,
        )}
      >
        <CircleCheckBig className="text-bg-neutral-primary size-4 lg:size-6" />
      </div>
    );
  }

  if (isActive) {
    return (
      <div
        className={cn(
          "border-border-input-primary-pressed bg-bg-neutral-secondary flex shrink-0 items-center justify-center rounded-full border",
          CIRCLE_SIZE,
        )}
      >
        <StepIcon icon={Icon} className="text-border-input-primary-pressed" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        "border-border-neutral-secondary bg-bg-neutral-secondary flex shrink-0 items-center justify-center rounded-full border",
        CIRCLE_SIZE,
      )}
    >
      <StepIcon icon={Icon} className="text-text-neutral-tertiary" />
    </div>
  );
}

interface StepConnectorProps {
  isComplete: boolean;
  className: string;
  direction: ConnectorDirection;
}

function StepConnector({
  isComplete,
  className,
  direction,
}: StepConnectorProps) {
  if (isComplete) {
    return <div className={cn("bg-border-input-primary-pressed", className)} />;
  }

  return (
    <div
      className={className}
      style={{
        backgroundImage: `repeating-linear-gradient(${direction}, var(--color-bg-data-muted) 0px, var(--color-bg-data-muted) 4px, transparent 4px, transparent 8px)`,
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
  // Size classes win over the custom SVGs' width/height attributes.
  if (isCustomSvgIcon(Icon)) {
    return <Icon size={24} className={cn("size-4 lg:size-6", className)} />;
  }
  return <Icon className={cn("size-4 lg:size-6", className)} />;
}

function isCustomSvgIcon(
  icon: IconComponent,
): icon is (props: IconSvgProps) => ReactElement {
  return !("displayName" in icon && typeof icon.displayName === "string");
}
