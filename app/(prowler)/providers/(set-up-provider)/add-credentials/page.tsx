import React from "react";

import { NavigationHeader } from "@/components/ui";

export default function AddCredentialsPage() {
  return (
    <>
      <NavigationHeader
        title="Connect your account via credentials"
        icon="bi:arrow-left"
        href="/providers/connect-account"
      />
    </>
  );
}
