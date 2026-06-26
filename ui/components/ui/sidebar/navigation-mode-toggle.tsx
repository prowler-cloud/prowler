"use client";

import { LayoutDashboard } from "lucide-react";
import { useRouter } from "next/navigation";

import { LighthouseIcon } from "@/components/icons/Icons";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  SIDEBAR_NAVIGATION_MODE,
  type SidebarNavigationMode,
} from "@/hooks/use-sidebar";
import { cn } from "@/lib/utils";

export function SidebarNavigationModeToggle({
  isOpen,
  value,
  onChange,
}: {
  isOpen: boolean;
  value: SidebarNavigationMode;
  onChange: (value: SidebarNavigationMode) => void;
}) {
  const router = useRouter();
  const modes = [
    {
      value: SIDEBAR_NAVIGATION_MODE.BROWSE,
      label: "Home",
      icon: LayoutDashboard,
    },
    {
      value: SIDEBAR_NAVIGATION_MODE.CHAT,
      label: "Chat",
      icon: LighthouseIcon,
    },
  ] as const;

  const handleModeChange = (mode: SidebarNavigationMode) => {
    onChange(mode);
    if (mode === SIDEBAR_NAVIGATION_MODE.CHAT) {
      router.push("/lighthouse");
    }
  };

  return (
    <div className={cn("mt-3 shrink-0 px-2", !isOpen && "flex justify-center")}>
      <div
        className={cn(
          "border-border-neutral-secondary bg-bg-neutral-secondary flex rounded-[8px] border p-1",
          isOpen ? "w-full" : "flex-col",
        )}
      >
        {modes.map((mode) => {
          const Icon = mode.icon;
          const active = value === mode.value;
          const button = (
            <button
              key={mode.value}
              type="button"
              aria-label={mode.label}
              className={cn(
                "flex h-8 items-center justify-center rounded-[6px] px-2 text-sm transition-colors",
                isOpen ? "min-w-0 flex-1 gap-2" : "w-8",
                active
                  ? "bg-bg-neutral-tertiary text-text-neutral-primary"
                  : "text-text-neutral-secondary hover:text-text-neutral-primary",
              )}
              onClick={() => handleModeChange(mode.value)}
            >
              <Icon className="size-4 shrink-0" />
              {isOpen && <span className="truncate">{mode.label}</span>}
            </button>
          );

          if (isOpen) {
            return button;
          }

          return (
            <Tooltip key={mode.value} delayDuration={100}>
              <TooltipTrigger asChild>{button}</TooltipTrigger>
              <TooltipContent side="right">{mode.label}</TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
}
