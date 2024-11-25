import "@/styles/globals.css";

import { Spacer } from "@nextui-org/react";
import React from "react";

import { WorkflowAddProvider } from "@/components/providers/workflow";
import { NavigationHeader } from "@/components/ui";

interface ProviderLayoutProps {
  children: React.ReactNode;
}

export default function ProviderLayout({ children }: ProviderLayoutProps) {
  return (
    <>
      <NavigationHeader
        title="Connect your cloud account"
        icon="icon-park-outline:close-small"
        href="/providers"
      />
      <Spacer y={16} />
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
        <div className="order-1 my-auto hidden h-full lg:col-span-4 lg:col-start-2 lg:block">
          <WorkflowAddProvider />
        </div>
        <div className="order-2 my-auto lg:col-span-5 lg:col-start-6">
          {children}
        </div>
      </div>
    </>
  );
}
