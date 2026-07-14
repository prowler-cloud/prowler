"use client";

import { Cloud } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { LighthouseV2SidebarChat } from "@/app/(prowler)/lighthouse/_components/navigation";
import { InfoIcon, ProwlerShort } from "@/components/icons";
import { CollapsibleMenu } from "@/components/layout/sidebar/collapsible-menu";
import { MenuItem } from "@/components/layout/sidebar/menu-item";
import { Separator } from "@/components/shadcn";
import { Button } from "@/components/shadcn/button/button";
import { ScrollArea } from "@/components/shadcn/scroll-area/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { SidebarNavigationModeToggle } from "@/components/sidebar/navigation-mode-toggle";
import { useAuth } from "@/hooks";
import { useRuntimeConfig } from "@/hooks/use-runtime-config";
import { SIDEBAR_NAVIGATION_MODE, useSidebar } from "@/hooks/use-sidebar";
import { getMenuList } from "@/lib/menu-list";
import { LAUNCH_SCAN_HREF } from "@/lib/scans-navigation";
import { isCloud } from "@/lib/shared/env";
import { cn } from "@/lib/utils";
import { useCloudUpgradeStore, useScansStore } from "@/store";
import { GroupProps, type MenuSelectionHandler } from "@/types";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { RolePermissionAttributes } from "@/types/users";

interface MenuHideRule {
  label: string;
  condition: (permissions: RolePermissionAttributes) => boolean;
}

const MENU_HIDE_RULES: MenuHideRule[] = [
  {
    label: "Billing",
    condition: (permissions) => permissions?.manage_billing === false,
  },
  {
    label: "Integrations",
    condition: (permissions) => permissions?.manage_integrations === false,
  },
];

const filterMenus = (menuGroups: GroupProps[], labelsToHide: string[]) => {
  return menuGroups
    .map((group) => ({
      ...group,
      menus: group.menus
        .filter((menu) => !labelsToHide.includes(menu.label))
        .map((menu) => ({
          ...menu,
          submenus: menu.submenus?.filter(
            (submenu) => !labelsToHide.includes(submenu.label),
          ),
        })),
    }))
    .filter((group) => group.menus.length > 0);
};

interface SidebarMenuProps {
  isOpen: boolean;
  onSelect?: MenuSelectionHandler;
}

export const Menu = ({ isOpen, onSelect }: SidebarMenuProps) => {
  const pathname = usePathname();
  const { permissions } = useAuth();
  const openLaunchScanModal = useScansStore(
    (state) => state.openLaunchScanModal,
  );
  const isScansPage = pathname.startsWith("/scans");
  const { apiDocsUrl } = useRuntimeConfig();
  const isCloudEnv = isCloud();
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );
  const navigationMode = useSidebar((state) => state.navigationMode);
  const setNavigationMode = useSidebar((state) => state.setNavigationMode);

  const menuList = getMenuList({
    pathname,
    apiDocsUrl,
  });

  const labelsToHide = MENU_HIDE_RULES.filter((rule) =>
    rule.condition(permissions),
  ).map((rule) => rule.label);

  const filteredMenuList = filterMenus(menuList, labelsToHide);

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Launch Scan Button — mt-1 aligns its top with the main content panel
          (navbar 72px + py-4 = 88px), matching the fixed-height logo block. */}
      <div className="mt-1 flex shrink-0 justify-center px-2">
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            {isScansPage ? (
              <Button
                type="button"
                aria-label="Launch Scan"
                className={cn(isOpen ? "h-14 w-full p-1" : "w-14")}
                variant="default"
                size="default"
                onClick={() => {
                  openLaunchScanModal();
                  onSelect?.();
                }}
              >
                <LaunchScanButtonContent isOpen={isOpen} />
              </Button>
            ) : (
              <Button
                asChild
                className={cn(isOpen ? "h-14 w-full p-1" : "w-14")}
                variant="default"
                size="default"
              >
                <Link
                  href={LAUNCH_SCAN_HREF}
                  aria-label="Launch Scan"
                  onClick={onSelect}
                >
                  <LaunchScanButtonContent isOpen={isOpen} />
                </Link>
              </Button>
            )}
          </TooltipTrigger>
          {!isOpen && <TooltipContent side="right">Launch Scan</TooltipContent>}
        </Tooltip>
      </div>

      <SidebarNavigationModeToggle
        isOpen={isOpen}
        value={navigationMode}
        onChange={setNavigationMode}
        chatEnabled={isCloudEnv}
        onSelect={onSelect}
      />

      {/* Menu Items */}
      <div className="flex-1 overflow-hidden">
        {isCloudEnv && navigationMode === SIDEBAR_NAVIGATION_MODE.CHAT ? (
          <LighthouseV2SidebarChat isOpen={isOpen} />
        ) : (
          <ScrollArea className="h-full [&>div>div[style]]:block!">
            <nav className="mt-2 w-full lg:mt-6">
              <ul className="mx-2 flex flex-col items-start gap-1 pb-4">
                {filteredMenuList.map((group, groupIndex) => (
                  <li key={groupIndex} className="w-full">
                    {group.menus.map((menu, menuIndex) => (
                      <div key={menuIndex} className="w-full">
                        {menu.submenus && menu.submenus.length > 0 ? (
                          <CollapsibleMenu
                            icon={menu.icon}
                            label={menu.label}
                            submenus={menu.submenus}
                            defaultOpen={menu.defaultOpen}
                            isOpen={isOpen}
                            onSelect={onSelect}
                          />
                        ) : (
                          <MenuItem
                            href={menu.href}
                            label={menu.label}
                            icon={menu.icon}
                            active={menu.active}
                            target={menu.target}
                            tooltip={menu.tooltip}
                            isOpen={isOpen}
                            highlight={menu.highlight}
                            onSelect={onSelect}
                          />
                        )}
                      </div>
                    ))}
                  </li>
                ))}
              </ul>
            </nav>
          </ScrollArea>
        )}
      </div>

      {!isCloudEnv && (
        <div className="shrink-0 px-2 pt-4 pb-3">
          <Tooltip delayDuration={100}>
            <TooltipTrigger asChild>
              <Button
                type="button"
                variant="outline"
                aria-label="Explore Prowler Cloud"
                className={cn("w-full", isOpen ? "justify-center" : "px-0")}
                onClick={() => {
                  openCloudUpgrade(
                    CLOUD_UPGRADE_FEATURE.GENERAL,
                    onSelect?.() ?? undefined,
                  );
                }}
              >
                <Cloud aria-hidden="true" className="size-4" />
                {isOpen && <span>Explore Prowler Cloud</span>}
              </Button>
            </TooltipTrigger>
            {!isOpen && (
              <TooltipContent side="right">
                Explore Prowler Cloud
              </TooltipContent>
            )}
          </Tooltip>
        </div>
      )}

      {/* Footer */}
      <div className="text-muted-foreground border-border-neutral-secondary flex shrink-0 items-center justify-center gap-2 border-t pt-4 pb-2 text-center text-xs">
        {isOpen ? (
          <>
            <span>{process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION}</span>
            {isCloudEnv && (
              <>
                <Separator orientation="vertical" />
                <Link
                  href="https://status.prowler.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1"
                  onClick={onSelect}
                >
                  <InfoIcon size={16} />
                  <span className="text-muted-foreground font-normal opacity-80 transition-opacity hover:font-bold hover:opacity-100">
                    Service Status
                  </span>
                </Link>
              </>
            )}
          </>
        ) : (
          isCloudEnv && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Link
                  href="https://status.prowler.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center"
                  onClick={onSelect}
                >
                  <InfoIcon size={16} />
                </Link>
              </TooltipTrigger>
              <TooltipContent side="right">Service Status</TooltipContent>
            </Tooltip>
          )
        )}
      </div>
    </div>
  );
};

function LaunchScanButtonContent({ isOpen }: { isOpen: boolean }) {
  return (
    <span className={cn("flex items-center", isOpen && "gap-2.5")}>
      <ProwlerShort aria-hidden="true" className="size-5 text-current" />
      {isOpen && <span className="text-xl leading-8">Scan</span>}
    </span>
  );
}
