"use client";

import React from "react";

import { ConnectAccountForm } from "@/components/providers/workflow/forms";
import { NavigationHeader } from "@/components/ui";

export default function ConnectAccountPage() {
  return (
    <>
      <NavigationHeader
        title="Connect your cloud account"
        icon="icon-park-outline:close-small"
        href="/providers"
      />
      <ConnectAccountForm />
    </>
  );
}
