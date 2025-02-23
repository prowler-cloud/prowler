import { Icon } from "@iconify/react";

import { ThemeSwitch } from "@/components/ThemeSwitch";

import { SheetMenu } from "../sidebar-new/sheet-menu";
import { UserNav } from "../user-nav/user-nav";

interface NavbarProps {
  title: string;
  icon: string;
}

export function Navbar({ title, icon }: NavbarProps) {
  return (
    <header className="sticky top-0 z-10 w-full bg-background/95 shadow backdrop-blur supports-[backdrop-filter]:bg-background/60 dark:shadow-secondary">
      <div className="mx-4 flex h-14 items-center sm:mx-8">
        <div className="flex items-center space-x-2">
          <SheetMenu />
          <Icon
            className="text-default-500"
            height={24}
            icon={icon}
            width={24}
          />
          <h1 className="text-sm font-bold text-default-700">{title}</h1>
        </div>
        <div className="flex flex-1 items-center justify-end gap-3">
          <ThemeSwitch />
          <UserNav />
        </div>
      </div>
    </header>
  );
}
