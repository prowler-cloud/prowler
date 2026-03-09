import { ReactNode, Suspense } from "react";

import { FeedsServer } from "@/components/feeds";

import { FeedsLoadingFallback, NavbarClient } from "./navbar-client";

interface NavbarProps {
  title: string;
  icon?: string | ReactNode;
}

export function Navbar({ title, icon }: NavbarProps) {
  return (
    <NavbarClient
      title={title}
      icon={icon}
      feedsSlot={
        <Suspense fallback={<FeedsLoadingFallback />}>
          <FeedsServer limit={15} />
        </Suspense>
      }
    />
  );
}
