import { ReactNode } from "react";

import {
  Navbar,
  type OnboardingActionConfig,
} from "@/components/layout/nav-bar/navbar";

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
      <div className="py-4 pr-6">{children}</div>
    </>
  );
}
