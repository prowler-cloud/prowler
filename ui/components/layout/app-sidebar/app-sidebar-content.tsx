"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { LighthouseV2SidebarChat } from "@/app/(prowler)/lighthouse/_components/navigation";
import { ProwlerBrand } from "@/components/icons";
import { useAuth } from "@/hooks";
import { useRuntimeConfig } from "@/hooks/use-runtime-config";
import { isCloud } from "@/lib/shared/env";

import { useAppSidebarMode } from "./app-sidebar-mode-store";
import { AppSidebarModeToggle } from "./app-sidebar-mode-toggle";
import { LaunchScanAction } from "./launch-scan-action";
import { getNavigationConfig } from "./navigation-config";
import { SidebarFooter } from "./sidebar-footer";
import { SidebarNavigation } from "./sidebar-navigation";
import { APP_SIDEBAR_MODE, type AppSidebarSelectionHandler } from "./types";

interface AppSidebarContentProps {
  onSelect?: AppSidebarSelectionHandler;
}

export function AppSidebarContent({ onSelect }: AppSidebarContentProps) {
  const pathname = usePathname();
  const { permissions } = useAuth();
  const { apiDocsUrl } = useRuntimeConfig();
  const mode = useAppSidebarMode((state) => state.mode);
  const isCloudEnvironment = isCloud();
  const sections = getNavigationConfig({ pathname, apiDocsUrl, permissions });
  const showChat = isCloudEnvironment && mode === APP_SIDEBAR_MODE.CHAT;

  return (
    <div className="relative flex h-full min-h-0 w-full flex-col overflow-hidden">
      <div className="shrink-0 px-5 pt-8 pb-7">
        <Link
          href="/"
          aria-label="Prowler home"
          className="focus-visible:ring-button-primary/50 flex h-8 items-center rounded-md focus-visible:ring-2 focus-visible:outline-none"
          onClick={onSelect}
        >
          <ProwlerBrand />
        </Link>
      </div>

      <div className="shrink-0 space-y-3 px-3 pb-1">
        <LaunchScanAction onSelect={onSelect} />
        <AppSidebarModeToggle
          chatEnabled={isCloudEnvironment}
          onSelect={onSelect}
        />
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
        {showChat ? (
          <LighthouseV2SidebarChat isOpen />
        ) : (
          <SidebarNavigation sections={sections} onSelect={onSelect} />
        )}
      </div>

      <SidebarFooter
        isCloudEnvironment={isCloudEnvironment}
        onSelect={onSelect}
      />
    </div>
  );
}
