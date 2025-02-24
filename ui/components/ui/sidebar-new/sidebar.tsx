"use client";

import clsx from "clsx";
import { PanelsTopLeft } from "lucide-react";
import Link from "next/link";

import { ProwlerShort } from "@/components/icons";
import { ProwlerExtended } from "@/components/icons";
import { useSidebar } from "@/hooks/use-sidebar";
import { useStore } from "@/hooks/use-store";
import { cn } from "@/lib/utils";

import { Button } from "../button/button";
import { Menu } from "./menu";
import { SidebarToggle } from "./sidebar-toggle";

export function Sidebar() {
  const sidebar = useStore(useSidebar, (x) => x);
  if (!sidebar) return null;
  const { isOpen, toggleOpen, getOpenState, setIsHover, settings } = sidebar;
  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-20 h-screen -translate-x-full transition-[width] duration-300 ease-in-out lg:translate-x-0",
        !getOpenState() ? "w-[90px]" : "w-72",
        settings.disabled && "hidden",
      )}
    >
      <SidebarToggle isOpen={isOpen} setIsOpen={toggleOpen} />
      <div
        onMouseEnter={() => setIsHover(true)}
        onMouseLeave={() => setIsHover(false)}
        className="relative flex h-full flex-col overflow-y-auto px-3 py-4 shadow-md dark:shadow-primary"
      >
        <Button
          className={cn(
            "mb-1 transition-transform duration-300 ease-in-out",
            !getOpenState() ? "translate-x-1" : "translate-x-0",
          )}
          variant="link"
          asChild
        >
          <Link
            href="/"
            className={clsx(
              "mb-6 flex w-full flex-col items-center justify-center px-3",
              {
                "gap-0": !isOpen,
              },
            )}
          >
            <div
              className={clsx({
                hidden: isOpen,
              })}
            >
              <ProwlerShort />
            </div>
            <div
              className={clsx({
                hidden: !isOpen,
                "!mt-0": isOpen,
              })}
            >
              <ProwlerExtended />
            </div>
          </Link>
        </Button>

        <Menu isOpen={getOpenState()} />
      </div>
    </aside>
  );
}
