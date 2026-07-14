"use client";

import { Home } from "lucide-react";
import { useRouter } from "next/navigation";

import { LighthouseIcon } from "@/components/icons/Icons";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { CloudFeatureBadge } from "@/components/shared/cloud-feature-badge";
import {
  SIDEBAR_NAVIGATION_MODE,
  type SidebarNavigationMode,
} from "@/hooks/use-sidebar";
import { CLOUD_UPGRADE_FEATURE } from "@/lib/cloud-upgrade";
import { cn } from "@/lib/utils";
import { useCloudUpgradeStore } from "@/store";

export function SidebarNavigationModeToggle({
  isOpen,
  value,
  onChange,
  chatEnabled = true,
}: {
  isOpen: boolean;
  value: SidebarNavigationMode;
  onChange: (value: SidebarNavigationMode) => void;
  chatEnabled?: boolean;
}) {
  const router = useRouter();
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );
  const modes = [
    {
      value: SIDEBAR_NAVIGATION_MODE.BROWSE,
      label: "Home",
      icon: Home,
    },
    {
      value: SIDEBAR_NAVIGATION_MODE.CHAT,
      label: "Chat",
      icon: LighthouseIcon,
    },
  ] as const;

  const handleModeChange = (mode: SidebarNavigationMode, disabled: boolean) => {
    if (disabled) {
      openCloudUpgrade(CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI);
      return;
    }
    onChange(mode);
    if (mode === SIDEBAR_NAVIGATION_MODE.CHAT) {
      router.push("/lighthouse");
    }
  };

  return (
    <div className={cn("mt-4 shrink-0 px-2", !isOpen && "flex justify-center")}>
      <div
        className={cn(
          "border-border-input-primary bg-bg-input-primary dark:bg-input/30 flex gap-1 rounded-lg border p-1",
          isOpen ? "w-full" : "flex-col",
        )}
      >
        {modes.map((mode) => {
          const Icon = mode.icon;
          const active = value === mode.value;
          const disabled =
            mode.value === SIDEBAR_NAVIGATION_MODE.CHAT && !chatEnabled;
          const button = (
            <button
              key={mode.value}
              type="button"
              aria-label={mode.label}
              className={cn(
                "flex h-8 items-center justify-center rounded-[6px] border px-2 text-sm transition-all duration-200 ease-out",
                isOpen ? "min-w-0 gap-2" : "w-8",
                // The active segment grows (~55%) and gains a bordered, shadowed
                // "thumb"; the inactive one shrinks (~45%) and stays flat.
                active
                  ? "border-border-input-primary bg-bg-neutral-primary text-text-neutral-primary shadow-md"
                  : "text-text-neutral-secondary hover:text-text-neutral-primary border-transparent",
                isOpen && (active ? "flex-[11]" : "flex-[9]"),
                disabled && "text-text-neutral-secondary",
              )}
              onClick={() => handleModeChange(mode.value, disabled)}
            >
              <Icon className="size-4 shrink-0" />
              {isOpen && <span className="truncate">{mode.label}</span>}
              {isOpen && disabled && (
                <CloudFeatureBadge label="Cloud" size="sm" />
              )}
            </button>
          );

          const tooltipContent = disabled
            ? "Available in Prowler Cloud"
            : !isOpen
              ? mode.label
              : null;

          if (!tooltipContent) {
            return button;
          }

          return (
            <Tooltip key={mode.value} delayDuration={100}>
              <TooltipTrigger asChild>{button}</TooltipTrigger>
              <TooltipContent side="right">{tooltipContent}</TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
}
