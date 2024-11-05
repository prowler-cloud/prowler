import { redirect } from "next/navigation";
import React from "react";

import { getProvider } from "@/actions/providers";
import { TestConnectionForm } from "@/components/providers/workflow/forms";

interface Props {
  searchParams: { type: string; id: string };
}

export default async function TestConnectionPage({ searchParams }: Props) {
  const providerId = searchParams.id;

  if (!providerId) {
    redirect("/providers/connect-account");
  }

  const formData = new FormData();
  formData.append("id", providerId);

  const providerData = await getProvider(formData);

  return (
    <TestConnectionForm
      searchParams={searchParams}
      providerData={providerData}
    />
  );
}
