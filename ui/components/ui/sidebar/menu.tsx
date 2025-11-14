"use client";

import { Divider } from "@heroui/divider";
import { Ellipsis } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { AddIcon, InfoIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { CollapseMenuButton } from "@/components/ui/sidebar/collapse-menu-button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip/tooltip";
import { useAuth } from "@/hooks";
import { getMenuList } from "@/lib/menu-list";
import { cn } from "@/lib/utils";
import { useUIStore } from "@/store/ui/store";
import { GroupProps } from "@/types";
import { RolePermissionAttributes } from "@/types/users";

import { ScrollArea } from "../scroll-area/scroll-area";

interface MenuHideRule {
  label: string;
  condition: (permissions: RolePermissionAttributes) => boolean;
}

// Configuration for hiding menu items based on permissions
const MENU_HIDE_RULES: MenuHideRule[] = [
  {
    label: "Billing",
    condition: (permissions) => permissions?.manage_billing === false,
  },
  {
    label: "Integrations",
    condition: (permissions) => permissions?.manage_integrations === false,
  },
  // Add more rules as needed:
  // {
  //   label: "Users",
  //   condition: (permissions) => !permissions?.manage_users
  // },
  // {
  //   label: "Configuration",
  //   condition: (permissions) => !permissions?.manage_providers
  // },
];

const hideMenuItems = (menuGroups: GroupProps[], labelsToHide: string[]) => {
  return menuGroups.map((group) => ({
    ...group,
    menus: group.menus
      .filter((menu) => !labelsToHide.includes(menu.label))
      .map((menu) => ({
        ...menu,
        submenus:
          menu.submenus?.filter(
            (submenu) => !labelsToHide.includes(submenu.label),
          ) || [],
      })),
  }));
};

export const Menu = ({ isOpen }: { isOpen: boolean }) => {
  const pathname = usePathname();
  const { permissions } = useAuth();
  const { hasProviders, openMutelistModal, requestMutelistModalOpen } =
    useUIStore();
  const menuList = getMenuList({
    pathname,
    hasProviders,
    openMutelistModal,
    requestMutelistModalOpen,
  });

  const labelsToHide = MENU_HIDE_RULES.filter((rule) =>
    rule.condition(permissions),
  ).map((rule) => rule.label);

  const filteredMenuList = hideMenuItems(menuList, labelsToHide);

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="shrink-0 px-2">
        <Button
          asChild
          className={cn(isOpen ? "w-full" : "w-14")}
          variant="default"
          size="default"
        >
          <Link href="/scans" aria-label="Launch Scan">
            {isOpen ? "Launch Scan" : <AddIcon className="size-5" />}
          </Link>
        </Button>
      </div>
      <div className="flex-1 overflow-hidden">
        <ScrollArea className="h-full [&>div>div[style]]:block!">
          <nav className="mt-2 w-full lg:mt-6">
            <ul className="flex flex-col items-start gap-1 px-2 pb-4">
              {filteredMenuList.map(({ groupLabel, menus }, index) => (
                <li
                  className={cn("w-full", groupLabel ? "pt-2" : "")}
                  key={index}
                >
                  {(menus.length > 0 && isOpen && groupLabel) ||
                  isOpen === undefined ? (
                    <p className="text-muted-foreground max-w-[248px] truncate px-4 pb-2 text-xs font-normal">
                      {groupLabel}
                    </p>
                  ) : !isOpen && isOpen !== undefined && groupLabel ? (
                    <TooltipProvider>
                      <Tooltip delayDuration={100}>
                        <TooltipTrigger className="w-full">
                          <div className="flex w-full items-center justify-center">
                            <Ellipsis className="h-5 w-5" />
                          </div>
                        </TooltipTrigger>
                        <TooltipContent className="z-100" side="right">
                          <p>{groupLabel}</p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : (
                    <p className=""></p>
                  )}
                  {menus.map((menu, index) => {
                    const {
                      href,
                      label,
                      icon: Icon,
                      active,
                      submenus,
                      defaultOpen,
                      target,
                      tooltip,
                    } = menu;
                    return !submenus || submenus.length === 0 ? (
                      <div className="w-full" key={index}>
                        <TooltipProvider disableHoverableContent>
                          <Tooltip delayDuration={100}>
                            <TooltipTrigger asChild>
                              <Button
                                variant={
                                  (active === undefined &&
                                    pathname.startsWith(href)) ||
                                  active
                                    ? "secondary"
                                    : "ghost"
                                }
                                className={cn(
                                  isOpen ? "w-full justify-start" : "w-14",
                                )}
                                asChild
                              >
                                <Link href={href} target={target}>
                                  <span
                                    className={cn(
                                      isOpen === false ? "" : "mr-4",
                                    )}
                                  >
                                    <Icon size={18} />
                                  </span>
                                  {isOpen && (
                                    <p className="max-w-[200px] truncate">
                                      {label}
                                    </p>
                                  )}
                                </Link>
                              </Button>
                            </TooltipTrigger>
                            {tooltip && (
                              <TooltipContent side="right">
                                {tooltip}
                              </TooltipContent>
                            )}
                          </Tooltip>
                        </TooltipProvider>
                      </div>
                    ) : (
                      <div className="w-full" key={index}>
                        <CollapseMenuButton
                          icon={Icon}
                          label={label}
                          submenus={submenus}
                          isOpen={isOpen}
                          defaultOpen={defaultOpen ?? false}
                        />
                      </div>
                    );
                  })}
                </li>
              ))}
            </ul>
          </nav>
        </ScrollArea>
      </div>

      <div className="text-muted-foreground border-border-neutral-secondary flex shrink-0 items-center justify-center gap-2 border-t pt-4 pb-2 text-center text-xs">
        <span>{process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION}</span>
        {process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true" && (
          <>
            <Divider orientation="vertical" />
            <Link
              href="https://status.prowler.com"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1"
            >
              <InfoIcon size={16} />
              <span className="text-muted-foreground font-normal opacity-80 transition-opacity hover:font-bold hover:opacity-100">
                Service Status
              </span>
            </Link>
          </>
        )}
      </div>
    </div>
  );
};
