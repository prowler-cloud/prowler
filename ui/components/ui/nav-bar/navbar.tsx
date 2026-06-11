import { ReactNode, Suspense } from "react";

import { FeedsServer } from "@/components/feeds";

import {
  FeedsLoadingFallback,
  NavbarClient,
  type OnboardingActionConfig,
} from "./navbar-client";

export type { OnboardingActionConfig };

interface NavbarProps {
  title: string;
  icon?: string | ReactNode;
  onboardingAction?: OnboardingActionConfig;
}

export function Navbar({ title, icon, onboardingAction }: NavbarProps) {
  return (
    <NavbarClient
      title={title}
      icon={icon}
      onboardingAction={onboardingAction}
      feedsSlot={
        <Suspense key="feeds" fallback={<FeedsLoadingFallback />}>
          <FeedsServer limit={15} />
        </Suspense>
      }
    />
  );
}
