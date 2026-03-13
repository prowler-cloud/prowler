"use client";

import { Divider } from "@heroui/divider";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { AddIcon, InfoIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area/scroll-area";
import { CollapsibleMenu } from "@/components/ui/sidebar/collapsible-menu";
import { MenuItem } from "@/components/ui/sidebar/menu-item";
import { useAuth } from "@/hooks";
import { getMenuList } from "@/lib/menu-list";
import { cn } from "@/lib/utils";
import { GroupProps } from "@/types";
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

export const Menu = ({ isOpen }: { isOpen: boolean }) => {
  const pathname = usePathname();
  const { permissions } = useAuth();

  const menuList = getMenuList({
    pathname,
  });

  const labelsToHide = MENU_HIDE_RULES.filter((rule) =>
    rule.condition(permissions),
  ).map((rule) => rule.label);

  const filteredMenuList = filterMenus(menuList, labelsToHide);

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Launch Scan Button */}
      <div className="shrink-0 px-2">
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
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
          </TooltipTrigger>
          {!isOpen && <TooltipContent side="right">Launch Scan</TooltipContent>}
        </Tooltip>
      </div>

      {/* Menu Items */}
      <div className="flex-1 overflow-hidden">
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
                        />
                      )}
                    </div>
                  ))}
                </li>
              ))}
            </ul>
          </nav>
        </ScrollArea>
      </div>

      {/* Footer */}
      <div className="text-muted-foreground border-border-neutral-secondary flex shrink-0 items-center justify-center gap-2 border-t pt-4 pb-2 text-center text-xs">
        {isOpen ? (
          <>
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
          </>
        ) : (
          process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true" && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Link
                  href="https://status.prowler.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center"
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
