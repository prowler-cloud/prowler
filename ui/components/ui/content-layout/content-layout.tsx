import { ReactNode } from "react";

import { Navbar, type OnboardingActionConfig } from "../nav-bar/navbar";

interface ContentLayoutProps {
  title: string;
  icon?: string | ReactNode;
  onboardingAction?: OnboardingActionConfig;
  children: React.ReactNode;
}

export function ContentLayout({
  title,
  icon,
  onboardingAction,
  children,
}: ContentLayoutProps) {
  return (
    <>
      <Navbar title={title} icon={icon} onboardingAction={onboardingAction} />
      <div className="px-6 py-4 sm:px-8">{children}</div>
    </>
  );
}
