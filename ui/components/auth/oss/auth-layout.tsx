import { ReactNode } from "react";

import { ProwlerBrand } from "@/components/icons";

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

        <div className="relative z-10 mb-8 w-[200px]">
          <ProwlerBrand className="w-full" />
        </div>

        {/* Auth Form Container */}
        <div className="border-border-neutral-secondary dark:bg-bg-neutral-primary/85 relative z-10 flex w-full max-w-sm flex-col gap-4 rounded-[14px] border bg-white/90 px-8 py-10 shadow-sm md:max-w-md">
          {/* Header */}
          <p className="pb-2 text-xl font-medium">{title}</p>

          {/* Content */}
          {children}
        </div>
      </div>
    </div>
  );
};
