import { ReactNode } from "react";

import { ThemeSwitch } from "@/components/ThemeSwitch";

import { AuthBrand } from "./auth-brand";

interface AuthLayoutProps {
  title: string;
  footer?: ReactNode;
  children: ReactNode;
}

export const AuthLayout = ({ title, footer, children }: AuthLayoutProps) => {
  return (
    <div className="relative flex min-h-screen w-full overflow-x-hidden overflow-y-auto">
      <div className="relative flex w-full flex-col items-center justify-center px-4 py-24">
        <AuthBrand className="mb-8" />

        {/* Auth Form Container */}
        <div className="border-border-neutral-secondary bg-bg-neutral-secondary relative z-10 flex w-full max-w-sm flex-col gap-4 rounded-lg border px-8 py-9 md:max-w-md">
          {/* Header with Title and Theme Toggle */}
          <div className="flex items-center justify-between">
            <h1 className="pb-2 text-[22px] font-semibold tracking-[-0.02em]">
              {title}
            </h1>
            <ThemeSwitch aria-label="Toggle theme" />
          </div>

          {/* Content */}
          {children}
        </div>

        {footer && <div className="relative z-10 mt-6">{footer}</div>}
      </div>
    </div>
  );
};
