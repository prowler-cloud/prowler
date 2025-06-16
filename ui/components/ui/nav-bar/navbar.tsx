import { Icon } from "@iconify/react";
import { ReactNode } from "react";

import { ThemeSwitch } from "@/components/ThemeSwitch";
import { UserProfileProps } from "@/types";

import { SheetMenu } from "../sidebar/sheet-menu";
import { UserNav } from "../user-nav/user-nav";

interface NavbarProps {
  title: string;
  icon: string | ReactNode;
  user: UserProfileProps;
}

export function Navbar({ title, icon, user }: NavbarProps) {
  return (
    <header className="sticky top-0 z-10 w-full bg-background/95 shadow backdrop-blur supports-[backdrop-filter]:bg-background/60 dark:shadow-primary">
      <div className="mx-4 flex h-14 items-center sm:mx-8">
        <div className="flex items-center space-x-2">
          <SheetMenu />
          {typeof icon === "string" ? (
            <Icon
              className="text-default-500"
              height={24}
              icon={icon}
              width={24}
            />
          ) : (
            <div className="flex h-10 w-10 items-center justify-center [&>*]:h-full [&>*]:w-full">
              {icon}
            </div>
          )}
          <h1 className="text-sm font-bold text-default-700">{title}</h1>
        </div>
        <div className="flex flex-1 items-center justify-end gap-3">
          <ThemeSwitch />
          <UserNav user={user} />
        </div>
      </div>
    </header>
  );
}
