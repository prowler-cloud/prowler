import "@/styles/globals.css";

import { GoogleTagManager } from "@next/third-parties/google";
import { Metadata, Viewport } from "next";
import { connection } from "next/server";
import { ReactNode, Suspense } from "react";

import { RuntimePublicConfig } from "@/components/runtime-config/runtime-public-config";
import { NavigationProgress, Toaster } from "@/components/ui";
import { fontSans } from "@/config/fonts";
import { siteConfig } from "@/config/site";
import { cn } from "@/lib";

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
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "white" },
    { media: "(prefers-color-scheme: dark)", color: "black" },
  ],
};

export default async function AuthLayout({
  children,
}: {
  children: ReactNode;
}) {
  // Force dynamic rendering so the read below resolves from the container env
  // at request time rather than being snapshotted at build (independent of the
  // <RuntimePublicConfig/> island's own connection() call).
  await connection();

  // Server-side runtime read. Empty/unset id ⇒ GoogleTagManager is not mounted
  const gtmId = process.env.WEB_APP_GOOGLE_TAG_MANAGER_ID;

  return (
    <html suppressHydrationWarning lang="en">
      <head>
        <RuntimePublicConfig />
      </head>
      <body
        suppressHydrationWarning
        className={cn(
          "bg-background min-h-screen font-sans antialiased",
          fontSans.variable,
        )}
      >
        <Providers themeProps={{ attribute: "class", defaultTheme: "dark" }}>
          <Suspense>
            <NavigationProgress />
          </Suspense>
          {children}
          <Toaster />
          {gtmId && <GoogleTagManager gtmId={gtmId} />}
        </Providers>
      </body>
    </html>
  );
}
