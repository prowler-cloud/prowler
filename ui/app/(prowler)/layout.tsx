import "@/styles/globals.css";

import { Metadata, Viewport } from "next";
import React, { Suspense, use } from "react";

import { getProfileInfo } from "@/actions/users/users";
import MainLayout from "@/components/ui/main-layout/main-layout";
import { Toaster } from "@/components/ui/toast";
import { fontSans } from "@/config/fonts";
import { siteConfig } from "@/config/site";
import { cn } from "@/lib/utils";

import { Providers } from "../providers";
import { SkeletonMainLayout } from "@/components/ui/main-layout/skeleton-main-layout";

export const metadata: Metadata = {
  title: {
    default: siteConfig.name,
    template: `%s - ${siteConfig.name}`,
  },
  description: siteConfig.description,
  icons: {
    icon: "/favicon.ico",
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "white" },
    { media: "(prefers-color-scheme: dark)", color: "black" },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = use(getProfileInfo());

  return (
    <html suppressHydrationWarning lang="en">
      <head />
      <body
        suppressHydrationWarning
        className={cn(
          "min-h-screen bg-background font-sans antialiased",
          fontSans.variable,
        )}
      >
        <Providers themeProps={{ attribute: "class", defaultTheme: "dark" }}>
          <Suspense fallback={<SkeletonMainLayout />}>
            <MainLayout user={user}>{children}</MainLayout>
          </Suspense>
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
