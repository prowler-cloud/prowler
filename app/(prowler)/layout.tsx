import "@/styles/globals.css";

import clsx from "clsx";
import { Metadata, Viewport } from "next";
import React from "react";

import { SidebarWrap } from "@/components";
import { fontSans } from "@/config/fonts";
import { siteConfig } from "@/config/site";

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

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html suppressHydrationWarning lang="en">
      <head />
      <body
        className={clsx(
          "min-h-screen bg-background font-sans antialiased",
          fontSans.variable,
        )}
      >
        <Providers themeProps={{ attribute: "class", defaultTheme: "dark" }}>
          <div className="flex items-center h-dvh w-full justify-center overflow-hidden">
            <SidebarWrap />
            <main className="w-full flex-1 flex-col p-4 mb-auto">
              {children}
            </main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
