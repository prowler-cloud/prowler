import "@/styles/globals.css";

import React from "react";

interface ProviderLayoutProps {
  children: React.ReactNode;
}

export default function ProviderLayout({ children }: ProviderLayoutProps) {
  return <>{children}</>;
}
