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

    <div className="relative z-10 mx-auto flex min-h-screen w-full max-w-6xl items-center justify-center px-6 py-10 sm:px-10">
      <div className="flex w-full items-center justify-center gap-10 lg:justify-between xl:gap-16">
        <div className="flex w-full max-w-sm flex-col">
          <div className="mb-6 flex w-full justify-center">
            <ProwlerExtended width={300} className="h-auto w-55 max-w-full" />
          </div>

          <AuthCard className="gap-4 px-7 py-9">
            <div className="flex items-center justify-between">
              <p className="pb-1 text-lg font-medium">{title}</p>
              <ThemeSwitch aria-label="Toggle theme" />
            </div>

            {children}
          </AuthCard>
        </div>

        <AuthReleaseHighlights />
      </div>
    </div>
  </main>
);
