"use client";

import { usePathname, useSearchParams } from "next/navigation";
import React from "react";

import { Progress } from "@/components/shadcn/progress";
import { cn } from "@/lib/utils";
import type { LighthouseProvider } from "@/types/lighthouse-v1";

import { getProviderConfig } from "../llm-provider-registry";

const steps = [
  {
    title: "Enter Credentials",
    description:
      "Enter your API key and configure connection settings for the LLM provider.",
    href: "/lighthouse/settings/connect",
  },
  {
    title: "Select Default Model",
    description:
      "Choose the default model to use for AI-powered features in Prowler.",
    href: "/lighthouse/settings/select-model",
  },
];

const ROUTE_CONFIG: Record<
  string,
  {
    stepIndex: number;
  }
> = {
  "/lighthouse/settings/connect": { stepIndex: 0 },
  "/lighthouse/settings/select-model": { stepIndex: 1 },
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
      <p className="text-text-neutral-tertiary mb-5 text-sm">
        {isEditMode
          ? "Update your LLM provider configuration and settings."
          : "Follow these steps to configure your LLM provider and enable AI-powered features."}
      </p>
      <div className="mb-5 flex flex-col gap-2 px-0.5">
        <div className="flex items-center justify-between">
          <span className="text-sm">Steps</span>
          <span className="text-button-primary text-sm">
            {`${currentStep + 1} of ${steps.length}`}
          </span>
        </div>
        <Progress
          aria-label="Steps"
          value={((currentStep + 1) / steps.length) * 100}
          indicatorClassName="bg-button-primary"
        />
      </div>
      <nav aria-label="Progress">
        <ol className="flex flex-col gap-y-3">
          {steps.map((step, index) => {
            const isActive = index === currentStep;
            const isComplete = index < currentStep;

            return (
              <li
                key={step.title}
                className="border-border-neutral-primary rounded-[14px] border px-3 py-2.5"
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
                        "text-text-neutral-tertiary border-border-neutral-primary bg-transparent",
                    )}
                  >
                    {index + 1}
                  </div>
                  <div className="flex-1 text-left">
                    <div
                      className={cn(
                        "text-base font-medium",
                        isActive || isComplete
                          ? "text-text-neutral-primary"
                          : "text-text-neutral-tertiary",
                      )}
                    >
                      {step.title}
                    </div>
                    <div
                      className={cn(
                        "text-sm",
                        isActive || isComplete
                          ? "text-text-neutral-secondary"
                          : "text-text-neutral-tertiary",
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
      <div className="h-4" />
    </section>
  );
};
