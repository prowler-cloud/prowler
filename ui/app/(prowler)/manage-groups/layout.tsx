import "@/styles/globals.css";

import React from "react";

import { ContentLayout } from "@/components/ui";

interface ProviderLayoutProps {
  children: React.ReactNode;
}

export default function ProviderLayout({ children }: ProviderLayoutProps) {
  return (
    <ContentLayout title="Manage Groups" icon="lucide:group">
      {children}
    </ContentLayout>
  );
}
