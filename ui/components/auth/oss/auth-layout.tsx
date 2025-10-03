import { ReactNode } from "react";

import { ProwlerExtended } from "@/components/icons";
import { ThemeSwitch } from "@/components/ThemeSwitch";

interface AuthLayoutProps {
  title: string;
  children: ReactNode;
}

export const AuthLayout = ({ title, children }: AuthLayoutProps) => {
  return (
    <div className="relative flex h-screen w-screen">
      <div className="relative flex w-full items-center justify-center lg:w-full">
        {/* Background Pattern */}
        <div className="absolute h-full w-full bg-[radial-gradient(#6af400_1px,transparent_1px)] mask-[radial-gradient(ellipse_50%_50%_at_50%_50%,#000_10%,transparent_80%)] bg-size-[16px_16px]"></div>

        {/* Auth Form Container */}
        <div className="rounded-large border-divider shadow-small dark:bg-background/85 relative z-10 flex w-full max-w-sm flex-col gap-4 border bg-white/90 px-8 py-10 md:max-w-md">
          {/* Prowler Logo */}
          <div className="absolute -top-[100px] left-1/2 z-10 flex h-fit w-fit -translate-x-1/2">
            <ProwlerExtended width={300} />
          </div>

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
