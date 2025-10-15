"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { SelectModel } from "@/components/lighthouse/select-model";

function SelectModelContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const provider = searchParams.get("provider") || "";

  return (
    <SelectModel
      provider={provider}
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
