import { redirect } from "next/navigation";
import React from "react";

import { getProvider } from "@/actions/providers";
import { LaunchScanForm } from "@/components/providers/workflow/forms";

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
    <LaunchScanForm searchParams={searchParams} providerData={providerData} />
  );
}
