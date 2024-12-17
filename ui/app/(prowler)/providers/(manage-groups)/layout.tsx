import "@/styles/globals.css";

import { Spacer } from "@nextui-org/react";
import React from "react";

import { NavigationHeader } from "@/components/ui";

interface ProviderLayoutProps {
  children: React.ReactNode;
}

export default function ProviderLayout({ children }: ProviderLayoutProps) {
  return (
    <>
      <NavigationHeader
        title="Manage providers groups"
        icon="icon-park-outline:close-small"
        href="/providers"
      />
      <Spacer y={16} />
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">{children}</div>
    </>
  );
}
