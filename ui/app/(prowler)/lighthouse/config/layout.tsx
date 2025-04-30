import "@/styles/globals.css";

import React from "react";

import { ContentLayout } from "@/components/ui";

interface ChatbotConfigLayoutProps {
  children: React.ReactNode;
}

export default function ChatbotConfigLayout({
  children,
}: ChatbotConfigLayoutProps) {
  return (
    <ContentLayout title="Configure Chatbot" icon="lucide:settings">
      {children}
    </ContentLayout>
  );
}
