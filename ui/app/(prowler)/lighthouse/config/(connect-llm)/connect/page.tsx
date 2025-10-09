"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { ConnectLLMProvider } from "@/components/lighthouse/connect-llm-provider";

function ConnectContent() {
  const searchParams = useSearchParams();
  const provider = searchParams.get("provider") || "";

  return <ConnectLLMProvider provider={provider} />;
}

export default function ConnectLLMProviderPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ConnectContent />
    </Suspense>
  );
}
