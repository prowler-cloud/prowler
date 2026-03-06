"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { ConnectLLMProvider } from "@/components/lighthouse/connect-llm-provider";
import { SelectBedrockAuthMethod } from "@/components/lighthouse/select-bedrock-auth-method";
import type { LighthouseProvider } from "@/types/lighthouse";

export const BEDROCK_AUTH_MODES = {
  IAM: "iam",
  API_KEY: "api_key",
} as const;

type BedrockAuthMode =
  (typeof BEDROCK_AUTH_MODES)[keyof typeof BEDROCK_AUTH_MODES];

function ConnectContent() {
  const searchParams = useSearchParams();
  const provider = searchParams.get("provider") as LighthouseProvider | null;
  const mode = searchParams.get("mode") || "create";
  const auth = searchParams.get("auth") as BedrockAuthMode | null;

  if (!provider) {
    return null;
  }

  const isBedrockCreateMode = provider === "bedrock" && mode !== "edit";

  if (isBedrockCreateMode && !auth) {
    return <SelectBedrockAuthMethod />;
  }

  const initialAuthMode = isBedrockCreateMode && auth ? auth : undefined;

  return (
    <ConnectLLMProvider
      provider={provider}
      mode={mode}
      initialAuthMode={initialAuthMode}
    />
  );
}

export default function ConnectLLMProviderPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ConnectContent />
    </Suspense>
  );
}
