import { redirect } from "next/navigation";
import React from "react";

import { TestConnectionForm } from "@/components/providers/workflow/forms";

interface Props {
  searchParams: { type: string; id: string };
}

export default function TestConnectionPage({ searchParams }: Props) {
  if (!searchParams.id) {
    redirect("/providers/connect-account");
  }

  return <TestConnectionForm searchParams={searchParams} />;
}
