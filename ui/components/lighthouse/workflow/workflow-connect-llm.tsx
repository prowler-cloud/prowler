"use client";

import { Progress } from "@heroui/progress";
import { Spacer } from "@heroui/spacer";
import { usePathname, useSearchParams } from "next/navigation";
import React from "react";

import { cn } from "@/lib/utils";
import type { LighthouseProvider } from "@/types/lighthouse";

import { getProviderConfig } from "../llm-provider-registry";

const steps = [
  {
    title: "Enter Credentials",
    description:
      "Enter your API key and configure connection settings for the LLM provider.",
    href: "/lighthouse/config/connect",
  },
  {
    title: "Select Default Model",
    description:
      "Choose the default model to use for AI-powered features in Prowler.",
    href: "/lighthouse/config/select-model",
  },
];

const ROUTE_CONFIG: Record<
  string,
  {
    stepIndex: number;
  }
> = {
  "/lighthouse/config/connect": { stepIndex: 0 },
  "/lighthouse/config/select-model": { stepIndex: 1 },
};

export const WorkflowConnectLLM = () => {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const config = ROUTE_CONFIG[pathname] || { stepIndex: 0 };
  const currentStep = config.stepIndex;

  const provider = searchParams.get("provider") as LighthouseProvider | null;
  const mode = searchParams.get("mode");
  const isEditMode = mode === "edit";

  // Get provider name from registry
  const providerConfig = provider ? getProviderConfig(provider) : null;
  const providerName = providerConfig?.name || "LLM Provider";

  return (
    <section className="max-w-sm">
      <h1 className="mb-2 text-xl font-medium" id="getting-started">
        {isEditMode ? `Configure ${providerName}` : `Connect ${providerName}`}
      </h1>
      <p className="text-small text-default-500 mb-5">
        {isEditMode
          ? "Update your LLM provider configuration and settings."
          : "Follow these steps to configure your LLM provider and enable AI-powered features."}
      </p>
      <Progress
        classNames={{
          base: "px-0.5 mb-5",
          label: "text-small",
          value: "text-small text-button-primary",
          indicator: "bg-button-primary",
        }}
        label="Steps"
        maxValue={steps.length}
        minValue={0}
        showValueLabel={true}
        size="md"
        value={currentStep + 1}
        valueLabel={`${currentStep + 1} of ${steps.length}`}
      />
      <nav aria-label="Progress">
        <ol className="flex flex-col gap-y-3">
          {steps.map((step, index) => {
            const isActive = index === currentStep;
            const isComplete = index < currentStep;

            return (
              <li
                key={step.title}
                className="border-border-neutral-primary rounded-large border px-3 py-2.5"
              >
                <div className="flex items-center gap-4">
                  <div
                    className={cn(
                      "flex h-[34px] w-[34px] items-center justify-center rounded-full border text-sm font-semibold",
                      isComplete &&
                        "bg-button-primary border-button-primary text-white",
                      isActive &&
                        "border-button-primary text-button-primary bg-transparent",
                      !isActive &&
                        !isComplete &&
                        "text-default-500 border-border-neutral-primary bg-transparent",
                    )}
                  >
                    {index + 1}
                  </div>
                  <div className="flex-1 text-left">
                    <div
                      className={cn(
                        "text-medium font-medium",
                        isActive || isComplete
                          ? "text-default-foreground"
                          : "text-default-500",
                      )}
                    >
                      {step.title}
                    </div>
                    <div
                      className={cn(
                        "text-small",
                        isActive || isComplete
                          ? "text-default-600"
                          : "text-default-500",
                      )}
                    >
                      {step.description}
                    </div>
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      </nav>
      <Spacer y={4} />
    </section>
  );
};
