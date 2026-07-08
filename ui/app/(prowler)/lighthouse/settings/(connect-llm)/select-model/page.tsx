"use client";

import { redirect, useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { SelectModel } from "@/components/lighthouse-v1/select-model";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import type { LighthouseProvider } from "@/types/lighthouse-v1";

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
      onSelect={() => router.push(LIGHTHOUSE_ROUTE.SETTINGS)}
    />
  );
}

export default function SelectModelPage() {
  if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
    redirect(LIGHTHOUSE_ROUTE.SETTINGS);
  }

  return (
    <Suspense fallback={<div>Loading...</div>}>
      <SelectModelContent />
    </Suspense>
  );
}
