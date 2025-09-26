import { redirect } from "next/navigation";
import React, { Suspense } from "react";

import { getProvider } from "@/actions/providers";
import { SkeletonProviderWorkflow } from "@/components/providers/workflow";
import { TestConnectionForm } from "@/components/providers/workflow/forms";

interface Props {
  searchParams: Promise<{ type: string; id: string; updated: string }>;
}

export default async function TestConnectionPage({ searchParams }: Props) {
  const resolvedSearchParams = await searchParams;
  const providerId = resolvedSearchParams.id;

  if (!providerId) {
    redirect("/providers/connect-account");
  }

  return (
    <Suspense fallback={<SkeletonProviderWorkflow />}>
      <SSRTestConnection searchParams={resolvedSearchParams} />
    </Suspense>
  );
}

async function SSRTestConnection({
  searchParams,
}: {
  searchParams: { type: string; id: string; updated: string };
}) {
  const formData = new FormData();
  formData.append("id", searchParams.id);

  const providerData = await getProvider(formData);
  if (providerData.errors) {
    redirect("/providers/connect-account");
  }

  return (
    <TestConnectionForm
      searchParams={searchParams}
      providerData={providerData}
    />
  );
}
