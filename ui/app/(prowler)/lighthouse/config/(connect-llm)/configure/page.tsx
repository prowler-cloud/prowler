"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

function ConfigureContent() {
  const searchParams = useSearchParams();
  const provider = searchParams.get("provider") || "";

  const providerName =
    provider === "openai"
      ? "OpenAI"
      : provider === "bedrock"
        ? "Amazon Bedrock"
        : provider === "openai-compatible"
          ? "OpenAI Compatible"
          : "LLM Provider";

  return (
    <div className="flex w-full flex-col gap-6">
      <div>
        <h2 className="mb-2 text-xl font-semibold">Configure {providerName}</h2>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Provider configuration options will be available here soon.
        </p>
      </div>

      <div className="rounded-lg border border-gray-200 bg-gray-50 p-8 text-center dark:border-gray-700 dark:bg-gray-800">
        <p className="text-gray-600 dark:text-gray-400">
          Update credentials, change default model, and manage provider
          settings.
        </p>
      </div>
    </div>
  );
}

export default function ConfigureLLMProviderPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ConfigureContent />
    </Suspense>
  );
}
