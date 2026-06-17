"use client";

// Import Sentry client-side initialization
import "@/app/instrumentation.client";

import { SessionProvider } from "next-auth/react";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import { ThemeProviderProps } from "next-themes/dist/types";
import { ReactNode } from "react";

export interface ProvidersProps {
  children: ReactNode;
  themeProps?: ThemeProviderProps;
}

export function Providers({ children, themeProps }: ProvidersProps) {
  return (
    <SessionProvider>
      <NextThemesProvider {...themeProps}>{children}</NextThemesProvider>
    </SessionProvider>
  );
}
