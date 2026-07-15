"use client";

import { Home } from "lucide-react";
import { useRouter } from "next/navigation";

import { LighthouseIcon } from "@/components/icons/Icons";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { useAppSidebarMode } from "./app-sidebar-mode-store";
import {
  APP_SIDEBAR_MODE,
  type AppSidebarMode,
  type AppSidebarSelectionHandler,
} from "./types";

interface AppSidebarModeToggleProps {
  chatEnabled: boolean;
  onSelect?: AppSidebarSelectionHandler;
}

const MODES = [
  {
    value: APP_SIDEBAR_MODE.BROWSE,
    label: "Home",
    icon: Home,
  },
  {
    value: APP_SIDEBAR_MODE.CHAT,
    label: "Chat",
    icon: LighthouseIcon,
  },
] as const;

export function AppSidebarModeToggle({
  chatEnabled,
  onSelect,
}: AppSidebarModeToggleProps) {
  const router = useRouter();
  const mode = useAppSidebarMode((state) => state.mode);
  const setMode = useAppSidebarMode((state) => state.setMode);
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  const selectMode = (nextMode: AppSidebarMode) => {
    const isChatUpsell = nextMode === APP_SIDEBAR_MODE.CHAT && !chatEnabled;

    if (isChatUpsell) {
      openCloudUpgrade(
        CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI,
        onSelect?.() ?? undefined,
      );
      return;
    }

    setMode(nextMode);
    onSelect?.();

    if (nextMode === APP_SIDEBAR_MODE.CHAT) {
      router.push("/lighthouse");
    }
  };

  return (
    <div
      role="group"
      aria-label="Sidebar view"
      className="border-border-sidebar-toggle bg-bg-sidebar-toggle grid grid-cols-2 gap-1 rounded-xl border p-1"
    >
      {MODES.map((item) => {
        const Icon = item.icon;
        const isActive = item.value === mode;
        const isCloudUpsell =
          item.value === APP_SIDEBAR_MODE.CHAT && !chatEnabled;
        const button = (
          <button
            key={item.value}
            type="button"
            aria-label={item.label}
            aria-pressed={isActive}
            className={cn(
              "focus-visible:ring-button-primary/50 flex h-8 min-w-0 items-center justify-center gap-1.5 rounded-lg border px-2 text-sm transition-all focus-visible:ring-2 focus-visible:outline-none",
              isActive
                ? "border-border-sidebar-active bg-bg-sidebar-active text-text-neutral-primary shadow-sidebar-active"
                : "text-text-neutral-secondary hover:bg-bg-sidebar-hover hover:text-text-neutral-primary border-transparent",
              isCloudUpsell && "px-1.5",
            )}
            onClick={() => selectMode(item.value)}
          >
            <Icon aria-hidden="true" className="size-4 shrink-0" />
            <span>{item.label}</span>
            {isCloudUpsell && (
              <Badge variant="cloud" size="sm">
                Cloud
              </Badge>
            )}
          </button>
        );

        if (!isCloudUpsell) return button;

        return (
          <Tooltip key={item.value} delayDuration={100}>
            <TooltipTrigger asChild>{button}</TooltipTrigger>
            <TooltipContent side="right">
              Available in Prowler Cloud
            </TooltipContent>
          </Tooltip>
        );
      })}
    </div>
  );
}
