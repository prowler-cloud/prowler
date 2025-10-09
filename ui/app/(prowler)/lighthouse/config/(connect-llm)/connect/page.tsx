"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { ConnectLLMProvider } from "@/components/lighthouse/connect-llm-provider";

function ConnectContent() {
  const searchParams = useSearchParams();
  const provider = searchParams.get("provider") || "";
  const mode = searchParams.get("mode") || "create";

  return <ConnectLLMProvider provider={provider} mode={mode} />;
}

export default function ConnectLLMProviderPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ConnectContent />
    </Suspense>
  );
}
