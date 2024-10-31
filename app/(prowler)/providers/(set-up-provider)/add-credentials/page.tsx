import { redirect } from "next/navigation";
import React from "react";

import { ViaCredentialsForm } from "@/components/providers/workflow/forms";

interface Props {
  searchParams: { provider: string; id: string; via?: string };
}

export default function AddCredentialsPage({ searchParams }: Props) {
  if (
    !searchParams.provider ||
    !searchParams.id ||
    (searchParams.provider === "aws" && !searchParams.via)
  ) {
    redirect("/providers/connect-account");
  }

  const useCredentialsForm =
    (searchParams.provider === "aws" && searchParams.via === "credentials") ||
    (searchParams.provider !== "aws" && !searchParams.via);

  return (
    <>
      {useCredentialsForm && <ViaCredentialsForm searchParams={searchParams} />}
    </>
  );
}
