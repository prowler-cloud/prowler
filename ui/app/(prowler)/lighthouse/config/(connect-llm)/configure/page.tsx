"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect } from "react";

function ConfigureContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const provider = searchParams.get("provider") || "";

  useEffect(() => {
    if (provider) {
      // Simply redirect to connect workflow with edit mode
      router.push(`/lighthouse/config/connect?provider=${provider}&mode=edit`);
    } else {
      router.push("/lighthouse/config");
    }
  }, [provider, router]);

  return (
    <div className="flex h-64 items-center justify-center">
      <div className="text-sm text-gray-600 dark:text-gray-400">
        Loading provider configuration...
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
