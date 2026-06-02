import "@/styles/globals.css";

import * as Sentry from "@sentry/nextjs";
import { Metadata, Viewport } from "next";
import { ReactNode } from "react";

import { getProviders } from "@/actions/providers";
import { OnboardingGate } from "@/components/onboarding";
import MainLayout from "@/components/ui/main-layout/main-layout";
import { NavigationProgress } from "@/components/ui/navigation-progress";
import { Toaster } from "@/components/ui/toast";
import { fontSans } from "@/config/fonts";
import { siteConfig } from "@/config/site";
import { cn } from "@/lib/utils";
import { StoreInitializer } from "@/store/ui/store-initializer";

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
  const providersData = await getProviders({ page: 1, pageSize: 1 });
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
          <MainLayout>{children}</MainLayout>
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
