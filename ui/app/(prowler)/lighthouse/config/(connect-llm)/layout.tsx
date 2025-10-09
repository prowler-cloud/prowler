import "@/styles/globals.css";

import { Spacer } from "@heroui/spacer";
import React from "react";

import { WorkflowConnectLLM } from "@/components/lighthouse/workflow";
import { NavigationHeader } from "@/components/ui";

interface ConnectLLMLayoutProps {
  children: React.ReactNode;
}

export default function ConnectLLMLayout({ children }: ConnectLLMLayoutProps) {
  return (
    <>
      <NavigationHeader
        title="Connect LLM Provider"
        icon="icon-park-outline:close-small"
        href="/lighthouse/config"
      />
      <Spacer y={8} />
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
        <div className="order-1 my-auto hidden h-full lg:col-span-4 lg:col-start-2 lg:block">
          <WorkflowConnectLLM />
        </div>
        <div className="order-2 my-auto lg:col-span-5 lg:col-start-6">
          {children}
        </div>
      </div>
    </>
  );
}
