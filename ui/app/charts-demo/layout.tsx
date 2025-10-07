import "@/styles/globals.css";

import { Metadata } from "next";
import React from "react";

import { fontSans } from "@/config/fonts";
import { cn } from "@/lib";

export const metadata: Metadata = {
  title: "Graph Components Demo - Prowler",
  description: "Testing reusable chart components for the Prowler Dashboard",
};

export default function ChartsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={cn("font-sans antialiased", fontSans.variable)}>
        {children}
      </body>
    </html>
  );
}
