"use client";

import {
  CircleCheckBig,
  FolderGit2,
  KeyRound,
  Rocket,
} from "lucide-react";
import { usePathname } from "next/navigation";

import { ProwlerShort } from "@/components/icons/prowler/ProwlerIcons";
import { cn } from "@/lib/utils";
import { IconComponent, IconSvgProps } from "@/types/components";

interface StepConfig {
  label: string;
  description: string;
  icon: IconComponent;
}

const STEPS: StepConfig[] = [
  {
    label: "Link a Cloud Provider",
    description:
      "Enter the provider details you would like to add in Prowler.",
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

const ROUTE_TO_STEP: Record<string, number> = {
  "/providers/connect-account": 0,
  "/providers/add-credentials": 1,
  "/providers/test-connection": 2,
  "/providers/update-credentials": 1,
};

export const WorkflowAddProvider = () => {
  const pathname = usePathname();
  const currentStep = ROUTE_TO_STEP[pathname] ?? 0;

  return (
    <nav aria-label="Progress" className="flex max-w-sm flex-col gap-0">
      {STEPS.map((step, index) => {
        const isComplete = index < currentStep;
        const isActive = index === currentStep;
        const isInactive = index > currentStep;

        return (
          <div key={step.label} className="flex items-start gap-3">
            {/* Step indicator + connector line */}
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

            {/* Label + description */}
            <div className="flex flex-col gap-1 pt-[10px]">
              <span
                className={cn(
                  "text-lg leading-7 font-normal",
                  isActive && "text-[#f4f4f5]",
                  isComplete && "text-[#f4f4f5]",
                  isInactive && "text-[#f4f4f5]/60",
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
};

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
      <div className="border-border-input-primary-pressed flex size-[44px] shrink-0 items-center justify-center rounded-full border bg-[#121110]">
        <StepIcon
          icon={Icon}
          className="text-border-input-primary-pressed"
        />
      </div>
    );
  }

  return (
    <div className="flex size-[44px] shrink-0 items-center justify-center rounded-full border border-[#202020] bg-[#121110]">
      <StepIcon icon={Icon} className="text-[#525252]" />
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
