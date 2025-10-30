"use client";

import { BellRing } from "lucide-react";
import { ReactNode } from "react";

import { ThemeSwitch } from "@/components/ThemeSwitch";
import { BreadcrumbNavigation } from "@/components/ui";
import { Button } from "@/components/ui/button/button";

import { SheetMenu } from "../sidebar/sheet-menu";
import { UserNav } from "../user-nav/user-nav";

interface NavbarClientProps {
  title: string;
  icon: string | ReactNode;
  feedsSlot?: ReactNode;
}

export function NavbarClient({ title, icon, feedsSlot }: NavbarClientProps) {
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
          <ThemeSwitch />
          {feedsSlot}
          <UserNav />
        </div>
      </div>
    </header>
  );
}

export function FeedsLoadingFallback() {
  return (
    <Button
      variant="outline"
      className="relative h-8 w-8 rounded-full bg-transparent p-2"
      disabled
    >
      <BellRing size={18} className="animate-pulse text-slate-400" />
    </Button>
  );
}
