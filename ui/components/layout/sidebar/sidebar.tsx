"use client";

import clsx from "clsx";
import Link from "next/link";

import { ProwlerShort } from "@/components/icons";
import { ProwlerExtended } from "@/components/icons";
import { useSidebar } from "@/hooks/use-sidebar";
import { useStore } from "@/hooks/use-store";
import { cn } from "@/lib/utils";

import { Menu } from "./menu";

export function Sidebar() {
  const sidebar = useStore(useSidebar, (x) => x);
  if (!sidebar) return null;
  const { isOpen, getOpenState, setIsHover, settings } = sidebar;
  return (
    <aside
      className={cn(
        "fixed top-0 left-0 z-20 h-screen -translate-x-full transition-[width] duration-300 ease-in-out lg:translate-x-0",
        !getOpenState() ? "w-[90px]" : "w-[248px]",
        settings.disabled && "hidden",
      )}
    >
      <div
        onMouseEnter={() => setIsHover(true)}
        onMouseLeave={() => setIsHover(false)}
        className="no-scrollbar relative flex h-full flex-col overflow-x-hidden overflow-y-auto px-3 py-6"
      >
        <Link
          href="/"
          className={cn(
            "mb-6 flex w-full flex-col items-center justify-center px-3 transition-transform duration-300 ease-in-out",
            !getOpenState() ? "translate-x-1" : "translate-x-0",
            !isOpen && "gap-0",
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
              "mt-0!": isOpen,
            })}
          >
            <ProwlerExtended />
          </div>
        </Link>

        <Menu isOpen={getOpenState()} />
      </div>
    </aside>
  );
}
