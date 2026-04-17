import { ReactNode } from "react";

import { AnimatedDotsBackground } from "@/components/auth/oss/animated-dots-background";
import { AuthCard } from "@/components/auth/oss/auth-card";
import { AuthReleaseHighlights } from "@/components/auth/oss/auth-release-highlights";
import { ProwlerExtended } from "@/components/icons";
import { ThemeSwitch } from "@/components/ThemeSwitch";

interface AuthLayoutProps {
  title: string;
  children: ReactNode;
}

export const AuthLayout = ({ title, children }: AuthLayoutProps) => (
  <main className="relative min-h-screen w-full overflow-hidden">
    <AnimatedDotsBackground />

    <div className="relative z-10 grid min-h-screen grid-cols-1 lg:grid-cols-2">
      <div className="flex items-center justify-center px-6 py-10 sm:px-10">
        <div className="flex w-full max-w-sm flex-col">
          <div className="mb-6 flex w-full justify-center">
            <ProwlerExtended
              width={300}
              className="h-auto w-[220px] max-w-full"
            />
          </div>

          <AuthCard className="gap-3 px-6 py-8">
            <div className="flex items-center justify-between">
              <p className="pb-1 text-lg font-medium">{title}</p>
              <ThemeSwitch aria-label="Toggle theme" />
            </div>

            {children}
          </AuthCard>
        </div>
      </div>

      <AuthReleaseHighlights />
    </div>
  </main>
);
