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
  // Fail-open: if the scan fetch fails or returns no parseable data we treat
  // the user as already having scan data, so the banner's "Run a scan"
  // shortcut never nags someone whose scan state we can't determine.
  const hasCompletedScan = Array.isArray(scansByState?.data)
    ? scansByState.data.some(
        (scan: { attributes?: { state?: string } }) =>
          scan.attributes?.state === SCAN_STATES.COMPLETED,
      )
    : true;
  // Tri-state on purpose: a SUCCESSFUL fetch carries `data` (an array, possibly
  // empty); a FAILED/ambiguous fetch yields `undefined` (network error) or an
  // error envelope without `data`. Collapsing the failure to `false` would
  // force the mandatory onboarding gate onto an existing user during an API
  // outage, so we keep `undefined` distinct and let the gate fail open.
  //   - success with providers -> true
  //   - success, zero providers -> false
  //   - failed/ambiguous fetch  -> undefined
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
          {/* Store keeps a plain boolean: existing sidebar/empty-state
              behavior is unchanged. Only the gate gets the tri-state so it can
              fail open on an unknown provider signal. */}
          <StoreInitializer values={{ hasProviders: hasProviders ?? false }} />
          <OnboardingGate hasProviders={hasProviders} />
          {/* Layout-level watcher: subscribes to the onboarding-checkpoint
              store `open` flag. The flag is armed by the gate's "Get started"
              accept and raised explicitly when the provider wizard closes
              having connected a provider, so the checkpoint fires once after
              the wizard closes — never mid-wizard, and never for an established
              user who simply adds another provider. One mount point so it
              survives the post-connect navigation. */}
          <OnboardingCheckpointWatcher />
          {/* Persistent, non-blocking bottom banner shown only while a guided
              sequence is active. It self-hides otherwise and owns the manual
              Continue (advance + navigate) and Exit (stop) controls, replacing
              the old auto-advance that jumped to empty pages before a scan. */}
          <OnboardingSequenceBanner hasCompletedScan={hasCompletedScan} />
          <MainLayout>{children}</MainLayout>
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
