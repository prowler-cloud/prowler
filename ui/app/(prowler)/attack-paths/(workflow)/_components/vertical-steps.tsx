"use client";

import { useControlledState } from "@react-stately/utils";
import { domAnimation, LazyMotion, m } from "framer-motion";
import type {
  ComponentProps,
  CSSProperties,
  HTMLAttributes,
  ReactNode,
} from "react";
import { forwardRef } from "react";

import { cn } from "@/lib/utils";

export type VerticalStepProps = {
  className?: string;
  description?: ReactNode;
  title?: ReactNode;
};

export const STEP_COLORS = {
  primary: "primary",
  secondary: "secondary",
  success: "success",
  warning: "warning",
  danger: "danger",
  default: "default",
} as const;

type StepColor = (typeof STEP_COLORS)[keyof typeof STEP_COLORS];

export interface VerticalStepsProps extends HTMLAttributes<HTMLButtonElement> {
  /**
   * An array of steps.
   *
   * @default []
   */
  steps?: VerticalStepProps[];
  /**
   * The color of the steps.
   *
   * @default "primary"
   */
  color?: StepColor;
  /**
   * The current step index.
   */
  currentStep?: number;
  /**
   * The default step index.
   *
   * @default 0
   */
  defaultStep?: number;
  /**
   * Whether to hide the progress bars.
   *
   * @default false
   */
  hideProgressBars?: boolean;
  /**
   * The custom class for the steps wrapper.
   */
  className?: string;
  /**
   * The custom class for the step.
   */
  stepClassName?: string;
  /**
   * Callback function when the step index changes.
   */
  onStepChange?: (stepIndex: number) => void;
}

function CheckIcon(props: ComponentProps<"svg">) {
  return (
    <svg
      {...props}
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      viewBox="0 0 24 24"
    >
      <m.path
        animate={{ pathLength: 1 }}
        d="M5 13l4 4L19 7"
        initial={{ pathLength: 0 }}
        strokeLinecap="round"
        strokeLinejoin="round"
        transition={{
          delay: 0.2,
          type: "tween",
          ease: "easeOut",
          duration: 0.3,
        }}
      />
    </svg>
  );
}

export const VerticalSteps = forwardRef<HTMLButtonElement, VerticalStepsProps>(
  (
    {
      color = "primary",
      steps = [],
      defaultStep = 0,
      onStepChange,
      currentStep: currentStepProp,
      hideProgressBars = false,
      stepClassName,
      className,
      ...props
    },
    ref,
  ) => {
    const [currentStep, setCurrentStep] = useControlledState(
      currentStepProp,
      defaultStep,
      onStepChange,
    );

    let userColor;
    let fgColor;

    const colorsVars = [
      "[--active-fg-color:var(--step-fg-color)]",
      "[--active-border-color:var(--step-color)]",
      "[--active-color:var(--step-color)]",
      "[--complete-background-color:var(--step-color)]",
      "[--complete-border-color:var(--step-color)]",
      "[--inactive-border-color:var(--border-neutral-tertiary)]",
      "[--inactive-color:var(--border-neutral-tertiary)]",
    ];

    switch (color) {
      case "secondary":
        userColor =
          "[--step-color:var(--color-violet-600)] dark:[--step-color:var(--color-violet-400)]";
        fgColor = "[--step-fg-color:var(--color-white)]";
        break;
      case "success":
        userColor = "[--step-color:var(--bg-pass-primary)]";
        fgColor = "[--step-fg-color:var(--color-black)]";
        break;
      case "warning":
        userColor = "[--step-color:var(--bg-warning-primary)]";
        fgColor = "[--step-fg-color:var(--color-black)]";
        break;
      case "danger":
        userColor = "[--step-color:var(--bg-fail-primary)]";
        fgColor = "[--step-fg-color:var(--color-white)]";
        break;
      case "default":
        userColor =
          "[--step-color:var(--color-zinc-300)] dark:[--step-color:var(--color-zinc-600)]";
        fgColor = "[--step-fg-color:var(--text-neutral-primary)]";
        break;
      case "primary":
      default:
        userColor = "[--step-color:var(--bg-button-primary)]";
        fgColor = "[--step-fg-color:var(--color-black)]";
        break;
    }

    if (!className?.includes("--step-fg-color")) colorsVars.unshift(fgColor);
    if (!className?.includes("--step-color")) colorsVars.unshift(userColor);
    if (!className?.includes("--inactive-bar-color"))
      colorsVars.push("[--inactive-bar-color:var(--border-neutral-tertiary)]");

    const colors = colorsVars;

    return (
      <nav aria-label="Progress" className="max-w-fit">
        <ol className={cn("flex flex-col gap-y-3", colors, className)}>
          {steps?.map((step, stepIdx) => {
            const status =
              currentStep === stepIdx
                ? "active"
                : currentStep < stepIdx
                  ? "inactive"
                  : "complete";

            return (
              <li key={stepIdx} className="relative">
                <div className="flex w-full max-w-full items-center">
                  <button
                    key={stepIdx}
                    ref={ref}
                    aria-current={status === "active" ? "step" : undefined}
                    className={cn(
                      "group flex w-full cursor-pointer items-center justify-center gap-4 rounded-[14px] px-3 py-2.5",
                      stepClassName,
                    )}
                    onClick={() => setCurrentStep(stepIdx)}
                    {...props}
                  >
                    <div className="flex h-full items-center">
                      <LazyMotion features={domAnimation}>
                        <div className="relative">
                          <m.div
                            animate={status}
                            className={cn(
                              "text-text-neutral-primary relative flex h-[34px] w-[34px] items-center justify-center rounded-full border-2 text-lg font-semibold",
                              {
                                "shadow-lg": status === "complete",
                              },
                            )}
                            data-status={status}
                            initial={false}
                            transition={{ duration: 0.25 }}
                            variants={{
                              inactive: {
                                backgroundColor: "transparent",
                                borderColor: "var(--inactive-border-color)",
                                color: "var(--inactive-color)",
                              },
                              active: {
                                backgroundColor: "transparent",
                                borderColor: "var(--active-border-color)",
                                color: "var(--active-color)",
                              },
                              complete: {
                                backgroundColor:
                                  "var(--complete-background-color)",
                                borderColor: "var(--complete-border-color)",
                              },
                            }}
                          >
                            <div className="flex items-center justify-center">
                              {status === "complete" ? (
                                <CheckIcon className="h-6 w-6 text-(--active-fg-color)" />
                              ) : (
                                <span>{stepIdx + 1}</span>
                              )}
                            </div>
                          </m.div>
                        </div>
                      </LazyMotion>
                    </div>
                    <div className="flex-1 text-left">
                      <div>
                        <div
                          className={cn(
                            "text-text-neutral-primary text-base font-medium transition-[color,opacity] duration-300 group-active:opacity-70",
                            {
                              "text-text-neutral-tertiary":
                                status === "inactive",
                            },
                          )}
                        >
                          {step.title}
                        </div>
                        <div
                          className={cn(
                            "text-text-neutral-secondary text-xs transition-[color,opacity] duration-300 group-active:opacity-70 lg:text-sm",
                            {
                              "text-text-neutral-tertiary":
                                status === "inactive",
                            },
                          )}
                        >
                          {step.description}
                        </div>
                      </div>
                    </div>
                  </button>
                </div>
                {stepIdx < steps.length - 1 && !hideProgressBars && (
                  <div
                    aria-hidden="true"
                    className={cn(
                      "pointer-events-none absolute top-[calc(64px*var(--idx)+1)] left-3 flex h-1/2 -translate-y-1/3 items-center px-4",
                    )}
                    style={
                      {
                        "--idx": stepIdx,
                      } as CSSProperties
                    }
                  >
                    <div
                      className={cn(
                        "relative h-full w-0.5 bg-(--inactive-bar-color) transition-colors duration-300",
                        "after:absolute after:block after:h-0 after:w-full after:bg-(--active-border-color) after:transition-[height] after:duration-300 after:content-['']",
                        {
                          "after:h-full": stepIdx < currentStep,
                        },
                      )}
                    />
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      </nav>
    );
  },
);

VerticalSteps.displayName = "VerticalSteps";
