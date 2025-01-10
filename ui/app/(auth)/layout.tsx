import "@/styles/globals.css";

import { Metadata, Viewport } from "next";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { Toaster } from "@/components/ui";
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

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth();

  if (session?.user) {
    redirect("/");
  }

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
          {children}
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
