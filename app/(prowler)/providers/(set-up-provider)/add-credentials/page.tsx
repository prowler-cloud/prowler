import { redirect } from "next/navigation";
import React from "react";

import { AddCredentialsForm } from "@/components/providers/workflow/forms";

interface Props {
  searchParams: { provider: string; id: string };
}

export default function AddCredentialsPage({ searchParams }: Props) {
  if (!searchParams.provider || !searchParams.id) {
    redirect("/providers/connect-account");
  }

  return <AddCredentialsForm searchParams={searchParams} />;
}
