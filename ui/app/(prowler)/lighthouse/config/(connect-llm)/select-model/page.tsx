"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { SelectModel } from "@/components/lighthouse/select-model";
import type { LighthouseProvider } from "@/types/lighthouse";

function SelectModelContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const provider = searchParams.get("provider") as LighthouseProvider | null;
  const mode = searchParams.get("mode") || "create";

  if (!provider) {
    return null;
  }

  return (
    <SelectModel
      provider={provider}
      mode={mode}
      onSelect={() => router.push("/lighthouse/config")}
    />
  );
}

export default function SelectModelPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <SelectModelContent />
    </Suspense>
  );
}
