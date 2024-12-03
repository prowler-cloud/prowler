import { redirect } from "next/navigation";
import React from "react";

import {
  ViaCredentialsForm,
  ViaRoleForm,
} from "@/components/providers/workflow/forms";

interface Props {
  searchParams: { type: string; id: string; via?: string };
}

export default function AddCredentialsPage({ searchParams }: Props) {
  if (
    !searchParams.type ||
    !searchParams.id ||
    (searchParams.type === "aws" && !searchParams.via)
  ) {
    redirect("/providers/connect-account");
  }

  const useCredentialsForm =
    (searchParams.type === "aws" && searchParams.via === "credentials") ||
    (searchParams.type !== "aws" && !searchParams.via);

  const useRoleForm =
    searchParams.type === "aws" && searchParams.via === "role";

  return (
    <>
      {useCredentialsForm && <ViaCredentialsForm searchParams={searchParams} />}
      {useRoleForm && <ViaRoleForm searchParams={searchParams} />}
    </>
  );
}
