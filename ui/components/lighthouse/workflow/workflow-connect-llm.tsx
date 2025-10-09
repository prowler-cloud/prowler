"use client";

import { Progress } from "@heroui/progress";
import { Spacer } from "@heroui/spacer";
import { usePathname, useSearchParams } from "next/navigation";
import React from "react";

import { VerticalSteps } from "@/components/providers/workflow/vertical-steps";

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

  const providerParam = searchParams.get("provider");
  const providerName =
    providerParam === "openai"
      ? "OpenAI"
      : providerParam === "bedrock"
        ? "Amazon Bedrock"
        : providerParam === "openai-compatible"
          ? "OpenAI Compatible"
          : "LLM Provider";

  return (
    <section className="max-w-sm">
      <h1 className="mb-2 text-xl font-medium" id="getting-started">
        Connect {providerName}
      </h1>
      <p className="text-small text-default-500 mb-5">
        Follow these steps to configure your LLM provider and enable AI-powered
        features.
      </p>
      <Progress
        classNames={{
          base: "px-0.5 mb-5",
          label: "text-small",
          value: "text-small text-default-400",
        }}
        label="Steps"
        maxValue={steps.length - 1}
        minValue={0}
        showValueLabel={true}
        size="md"
        value={currentStep}
        valueLabel={`${currentStep + 1} of ${steps.length}`}
      />
      <VerticalSteps
        hideProgressBars
        currentStep={currentStep}
        stepClassName="border border-default-200 dark:border-default-50 aria-[current]:bg-default-100 dark:aria-[current]:bg-prowler-blue-800 cursor-default"
        steps={steps}
      />
      <Spacer y={4} />
    </section>
  );
};
