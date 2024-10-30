import React from "react";

import { AddCredentialsForm } from "@/components/providers/workflow/forms";

export default function AddCredentialsPage({
  searchParams,
}: {
  searchParams: { provider: string; id: string };
}) {
  return <AddCredentialsForm searchParams={searchParams} />;
}
