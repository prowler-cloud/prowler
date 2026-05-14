import { ReactNode } from "react";

import { ProwlerExtended } from "@/components/icons";
import { ThemeSwitch } from "@/components/ThemeSwitch";

interface AuthLayoutProps {
  title: string;
  children: ReactNode;
}

export const AuthLayout = ({ title, children }: AuthLayoutProps) => {
  return (
    <div className="relative flex min-h-screen w-full overflow-x-hidden overflow-y-auto">
      <div className="relative flex w-full flex-col items-center justify-center px-4 py-32">
        {/* Background Pattern */}
        <div
          className="absolute inset-0 mask-[radial-gradient(ellipse_50%_50%_at_50%_50%,#000_10%,transparent_80%)] bg-size-[16px_16px]"
          style={{
            backgroundImage:
              "radial-gradient(var(--bg-button-primary) 1px, transparent 1px)",
          }}
        ></div>

        {/* Prowler Logo */}
        <div className="relative z-10 mb-8 flex w-full max-w-[300px]">
          <ProwlerExtended width={300} className="h-auto w-full" />
        </div>

        {/* Auth Form Container */}
        <div className="rounded-large border-divider shadow-small dark:bg-background/85 relative z-10 flex w-full max-w-sm flex-col gap-4 border bg-white/90 px-8 py-10 md:max-w-md">
          {/* Header with Title and Theme Toggle */}
          <div className="flex items-center justify-between">
            <p className="pb-2 text-xl font-medium">{title}</p>
            <ThemeSwitch aria-label="Toggle theme" />
          </div>

          {/* Content */}
          {children}
        </div>
      </div>
    </div>
  );
};
