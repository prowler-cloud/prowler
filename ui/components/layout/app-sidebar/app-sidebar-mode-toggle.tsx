"use client";

import { Home } from "lucide-react";
import { usePathname, useRouter } from "next/navigation";

import { LighthouseIcon } from "@/components/icons/Icons";
import { NavigationButton } from "@/components/shadcn/navigation-button";
import {
  isLighthouseChatRoute,
  LIGHTHOUSE_ROUTE,
} from "@/lib/lighthouse-routes";

import {
  useAppSidebarMode,
  useHydratedAppSidebarMode,
} from "./app-sidebar-mode-store";
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
  const pathname = usePathname();
  const mode = useHydratedAppSidebarMode();
  const setMode = useAppSidebarMode((state) => state.setMode);
  const selectMode = (nextMode: AppSidebarMode) => {
    setMode(nextMode);
    onSelect?.();

    if (
      nextMode === APP_SIDEBAR_MODE.CHAT &&
      !isLighthouseChatRoute(pathname)
    ) {
      router.push(LIGHTHOUSE_ROUTE.CHAT);
    }
  };

  if (!chatEnabled) return null;

  return (
    <div
      role="group"
      aria-label="Sidebar view"
      className="border-border-sidebar-toggle bg-bg-sidebar-toggle grid grid-cols-2 gap-1 rounded-xl border p-1"
    >
      {MODES.map((item) => {
        const Icon = item.icon;
        const isActive = item.value === mode;
        const button = (
          <NavigationButton
            key={item.value}
            variant="toggle"
            active={isActive}
            aria-label={item.label}
            aria-pressed={isActive}
            onClick={() => selectMode(item.value)}
          >
            <Icon aria-hidden="true" className="size-4 shrink-0" />
            <span>{item.label}</span>
          </NavigationButton>
        );

        return button;
      })}
    </div>
  );
}
