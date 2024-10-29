import "@/styles/globals.css";

import React from "react";

import { Workflow } from "@/components/providers/workflow";

interface ProviderLayoutProps {
  children: React.ReactNode;
}

export default function ProviderLayout({ children }: ProviderLayoutProps) {
  return (
    <>
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
        <div className="order-1 my-auto hidden h-full lg:col-span-4 lg:block">
          <Workflow />
        </div>
        <div className="order-2 lg:col-span-8">{children}</div>
      </div>
    </>
  );
}
