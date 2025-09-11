"use client";

import { Divider } from "@nextui-org/react";
import { Ellipsis, LogOut } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { logOut } from "@/actions/auth";
import { AddIcon, InfoIcon } from "@/components/icons";
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

import { Button } from "../button/button";
import { CustomButton } from "../custom/custom-button";
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
  const { hasProviders, openMutelistModal } = useUIStore();
  const menuList = getMenuList({
    pathname,
    hasProviders,
    openMutelistModal,
  });

  const labelsToHide = MENU_HIDE_RULES.filter((rule) =>
    rule.condition(permissions),
  ).map((rule) => rule.label);

  const filteredMenuList = hideMenuItems(menuList, labelsToHide);

  return (
    <>
      <div className="px-2">
        <CustomButton
          asLink="/scans"
          className={cn(isOpen ? "w-full" : "w-fit")}
          ariaLabel="Launch Scan"
          variant="solid"
          color="action"
          size="md"
          endContent={isOpen ? <AddIcon size={20} /> : null}
        >
          {isOpen ? "Launch Scan" : <AddIcon size={20} />}
        </CustomButton>
      </div>
      <ScrollArea className="[&>div>div[style]]:!block">
        <nav className="mt-2 h-full w-full lg:mt-6">
          <ul className="flex min-h-[calc(100vh-16px-60px-40px-16px-32px-40px-32px-44px)] flex-col items-start space-y-1 px-2 lg:min-h-[calc(100vh-16px-60px-40px-16px-64px-16px-41px)]">
            {filteredMenuList.map(({ groupLabel, menus }, index) => (
              <li
                className={cn(
                  "w-full",
                  groupLabel ? "pt-2" : "",
                  index === filteredMenuList.length - 2 && "!mt-auto",
                )}
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
                  <p className="pb-2"></p>
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
                              className="mb-1 h-8 w-full justify-start"
                              asChild
                            >
                              <Link href={href} target={target}>
                                <span
                                  className={cn(isOpen === false ? "" : "mr-4")}
                                >
                                  <Icon size={18} />
                                </span>
                                <p
                                  className={cn(
                                    "max-w-[200px] truncate",
                                    isOpen === false
                                      ? "-translate-x-96 opacity-0"
                                      : "translate-x-0 opacity-100",
                                  )}
                                >
                                  {label}
                                </p>
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
      <div className="flex w-full grow items-end">
        <TooltipProvider disableHoverableContent>
          <Tooltip delayDuration={100}>
            <TooltipTrigger asChild>
              <Button
                onClick={() => logOut()}
                variant="outline"
                className="mt-5 h-10 w-full justify-center"
              >
                <span className={cn(isOpen === false ? "" : "mr-4")}>
                  <LogOut size={18} />
                </span>
                <p
                  className={cn(
                    "whitespace-nowrap",
                    isOpen === false ? "hidden opacity-0" : "opacity-100",
                  )}
                >
                  Sign out
                </p>
              </Button>
            </TooltipTrigger>
            {isOpen === false && (
              <TooltipContent side="right">Sign out</TooltipContent>
            )}
          </Tooltip>
        </TooltipProvider>
      </div>

      <div className="text-muted-foreground border-border mt-2 flex items-center justify-center gap-2 border-t pt-2 text-center text-xs">
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
    </>
  );
};
