import { redirect } from "next/navigation";
import React, { Suspense } from "react";

import { getProvider } from "@/actions/providers";
import { LaunchScanForm } from "@/components/providers/workflow/forms";
import { SkeletonProviderWorkflow } from "@/components/providers/workflow/skeleton-provider-workflow";

interface Props {
  searchParams: { type: string; id: string };
}

export default async function LaunchScanPage({ searchParams }: Props) {
  const providerId = searchParams.id;

  if (!providerId) {
    redirect("/providers/connect-account");
  }

  const formData = new FormData();
  formData.append("id", providerId);

  const providerData = await getProvider(formData);

  const isConnected = providerData?.data?.attributes?.connection?.connected;

  if (!isConnected) {
    redirect("/providers/connect-account");
  }

  return (
    <Suspense fallback={<SkeletonProviderWorkflow />}>
      <SSRLaunchScan searchParams={searchParams} />
    </Suspense>
  );
}

async function SSRLaunchScan({
  searchParams,
}: {
  searchParams: { type: string; id: string };
}) {
  const formData = new FormData();
  formData.append("id", searchParams.id);

  const providerData = await getProvider(formData);

  return (
    <LaunchScanForm searchParams={searchParams} providerData={providerData} />
  );
}
