"use client";

import { cn } from "@heroui/theme";
import { useControlledState } from "@react-stately/utils";
import { domAnimation, LazyMotion, m } from "framer-motion";
import type { ComponentProps } from "react";
import React from "react";

export type VerticalStepProps = {
  className?: string;
  description?: React.ReactNode;
  title?: React.ReactNode;
};

export interface VerticalStepsProps
  extends React.HTMLAttributes<HTMLButtonElement> {
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
  color?:
    | "primary"
    | "secondary"
    | "success"
    | "warning"
    | "danger"
    | "default";
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

export const VerticalSteps = React.forwardRef<
  HTMLButtonElement,
  VerticalStepsProps
>(
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

    const colors = React.useMemo(() => {
      let userColor;
      let fgColor;

      const colorsVars = [
        "[--active-fg-color:var(--step-fg-color)]",
        "[--active-border-color:var(--step-color)]",
        "[--active-color:var(--step-color)]",
        "[--complete-background-color:var(--step-color)]",
        "[--complete-border-color:var(--step-color)]",
        "[--inactive-border-color:hsl(var(--heroui-default-300))]",
        "[--inactive-color:hsl(var(--heroui-default-300))]",
      ];

      switch (color) {
        case "primary":
          userColor = "[--step-color:hsl(var(--heroui-primary))]";
          fgColor = "[--step-fg-color:hsl(var(--heroui-primary-foreground))]";
          break;
        case "secondary":
          userColor = "[--step-color:hsl(var(--heroui-secondary))]";
          fgColor = "[--step-fg-color:hsl(var(--heroui-secondary-foreground))]";
          break;
        case "success":
          userColor = "[--step-color:hsl(var(--heroui-success))]";
          fgColor = "[--step-fg-color:hsl(var(--heroui-success-foreground))]";
          break;
        case "warning":
          userColor = "[--step-color:hsl(var(--heroui-warning))]";
          fgColor = "[--step-fg-color:hsl(var(--heroui-warning-foreground))]";
          break;
        case "danger":
          userColor = "[--step-color:hsl(var(--heroui-error))]";
          fgColor = "[--step-fg-color:hsl(var(--heroui-error-foreground))]";
          break;
        case "default":
          userColor = "[--step-color:hsl(var(--heroui-default))]";
          fgColor = "[--step-fg-color:hsl(var(--heroui-default-foreground))]";
          break;
        default:
          userColor = "[--step-color:hsl(var(--heroui-primary))]";
          fgColor = "[--step-fg-color:hsl(var(--heroui-primary-foreground))]";
          break;
      }

      if (!className?.includes("--step-fg-color")) colorsVars.unshift(fgColor);
      if (!className?.includes("--step-color")) colorsVars.unshift(userColor);
      if (!className?.includes("--inactive-bar-color"))
        colorsVars.push(
          "[--inactive-bar-color:hsl(var(--heroui-default-300))]",
        );

      return colorsVars;
    }, [color, className]);

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
                      "group rounded-large flex w-full cursor-pointer items-center justify-center gap-4 px-3 py-2.5",
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
                              "border-medium text-large text-default-foreground relative flex h-[34px] w-[34px] items-center justify-center rounded-full font-semibold",
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
                                borderColor: "var(--bg-button-primary)",
                                color: "var(--bg-button-primary)",
                              },
                              complete: {
                                backgroundColor: "var(--bg-button-primary)",
                                borderColor: "var(--bg-button-primary)",
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
                            "text-medium text-default-foreground font-medium transition-[color,opacity] duration-300 group-active:opacity-70",
                            {
                              "text-default-500": status === "inactive",
                            },
                          )}
                        >
                          {step.title}
                        </div>
                        <div
                          className={cn(
                            "text-tiny text-default-600 lg:text-small transition-[color,opacity] duration-300 group-active:opacity-70",
                            {
                              "text-default-500": status === "inactive",
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
                    style={{
                      // @ts-expect-error
                      "--idx": stepIdx,
                    }}
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
