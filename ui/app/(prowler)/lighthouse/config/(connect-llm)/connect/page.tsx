"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { ConnectLLMProvider } from "@/components/lighthouse/connect-llm-provider";
import type { LighthouseProvider } from "@/types/lighthouse";

function ConnectContent() {
  const searchParams = useSearchParams();
  const provider = searchParams.get("provider") as LighthouseProvider | null;
  const mode = searchParams.get("mode") || "create";

  if (!provider) {
    return null;
  }

  return <ConnectLLMProvider provider={provider} mode={mode} />;
}

export default function ConnectLLMProviderPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ConnectContent />
    </Suspense>
  );
}
