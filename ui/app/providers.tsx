"use client";

import { NextUIProvider } from "@nextui-org/system";
import { useRouter } from "next/navigation";
import { SessionProvider } from "next-auth/react";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import { ThemeProviderProps } from "next-themes/dist/types";
import posthog from "posthog-js";
import { PostHogProvider as PHProvider } from "posthog-js/react";
import * as React from "react";

import { initializePostHog } from "@/lib/analytics";

export interface ProvidersProps {
  children: React.ReactNode;
  themeProps?: ThemeProviderProps;
}

export function Providers({ children, themeProps }: ProvidersProps) {
  const router = useRouter();

  // Initialize PostHog
  React.useMemo(() => {
    initializePostHog();
  }, []);

  return (
    <SessionProvider>
      <NextUIProvider navigate={router.push}>
        <NextThemesProvider {...themeProps}>
          <PHProvider client={posthog}>{children}</PHProvider>
        </NextThemesProvider>
      </NextUIProvider>
    </SessionProvider>
  );
}
