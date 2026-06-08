import "@/styles/globals.css";

import * as Sentry from "@sentry/nextjs";
import { Metadata, Viewport } from "next";
import { ReactNode } from "react";

import { getProviders } from "@/actions/providers";
import { getScansByState } from "@/actions/scans/scans";
import {
  OnboardingCheckpointWatcher,
  OnboardingGate,
  OnboardingSequenceBanner,
} from "@/components/onboarding";
import MainLayout from "@/components/ui/main-layout/main-layout";
import { NavigationProgress } from "@/components/ui/navigation-progress";
import { Toaster } from "@/components/ui/toast";
import { fontSans } from "@/config/fonts";
import { siteConfig } from "@/config/site";
import { cn } from "@/lib/utils";
import { StoreInitializer } from "@/store/ui/store-initializer";
import { SCAN_STATES } from "@/types/attack-paths";

import { Providers } from "../providers";

export const metadata: Metadata = {
  title: {
    default: siteConfig.name,
    template: `%s - ${siteConfig.name}`,
  },
  description: siteConfig.description,
  icons: {
    icon: "/favicon.ico",
  },
  other: {
    ...Sentry.getTraceData(),
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "white" },
    { media: "(prefers-color-scheme: dark)", color: "black" },
  ],
};

export default async function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  const [providersData, scansByState] = await Promise.all([
    getProviders({ page: 1, pageSize: 1 }),
    getScansByState(),
  ]);
  // Fail-open: unknown scan state is treated as "has data" so the banner never nags.
  const hasCompletedScan = Array.isArray(scansByState?.data)
    ? scansByState.data.some(
        (scan: { attributes?: { state?: string } }) =>
          scan.attributes?.state === SCAN_STATES.COMPLETED,
      )
    : true;
  // Tri-state: true = has providers, false = zero providers, undefined = fetch failed (gate fails open).
  const hasProviders =
    providersData?.data === undefined
      ? undefined
      : providersData.data.length > 0;

  return (
    <html suppressHydrationWarning lang="en">
      <head />
      <body
        suppressHydrationWarning
        className={cn(
          "bg-background min-h-screen font-sans antialiased",
          fontSans.variable,
        )}
      >
        <Providers themeProps={{ attribute: "class", defaultTheme: "dark" }}>
          <NavigationProgress />
          {/* Store uses boolean; gate receives tri-state to fail open on fetch errors. */}
          <StoreInitializer values={{ hasProviders: hasProviders ?? false }} />
          <OnboardingGate hasProviders={hasProviders} />
          {/* Single mount point so the watcher survives post-connect navigation. */}
          <OnboardingCheckpointWatcher />
          {/* Persistent banner shown only while a guided sequence is active. */}
          <OnboardingSequenceBanner hasCompletedScan={hasCompletedScan} />
          <MainLayout>{children}</MainLayout>
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
