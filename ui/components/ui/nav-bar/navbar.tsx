"use client";

import { ReactNode } from "react";

import { ThemeSwitch } from "@/components/ThemeSwitch";
import { BreadcrumbNavigation } from "@/components/ui";

import { SheetMenu } from "../sidebar/sheet-menu";
import { UserNav } from "../user-nav/user-nav";

interface NavbarProps {
  title: string;
  icon: string | ReactNode;
}

export function Navbar({ title, icon }: NavbarProps) {
  return (
    <header className="bg-background/95 supports-[backdrop-filter]:bg-background/60 dark:shadow-primary sticky top-0 z-10 w-full shadow backdrop-blur">
      <div className="mx-4 flex h-14 items-center sm:mx-8">
        <div className="flex items-center gap-2">
          <SheetMenu />
          <BreadcrumbNavigation
            mode="auto"
            title={title}
            icon={icon}
            paramToPreserve="scanId"
          />
        </div>
        <div className="flex flex-1 items-center justify-end gap-3">
          {/* TODO: Uncomment when this feature is enabled and ready for release */}
          {/* {process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true" && <FeedsDetail />} */}
          <ThemeSwitch />
          <UserNav />
        </div>
      </div>
    </header>
  );
}
