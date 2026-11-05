import "@/styles/globals.css";

import { Group } from "lucide-react";
import React from "react";

import { ContentLayout } from "@/components/shadcn/content-layout";

interface ProviderLayoutProps {
  children: React.ReactNode;
}

export default function ProviderLayout({ children }: ProviderLayoutProps) {
  return (
    <ContentLayout title="Manage Groups" icon={<Group />}>
      {children}
    </ContentLayout>
  );
}
