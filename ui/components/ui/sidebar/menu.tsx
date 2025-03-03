"use client";

import { Ellipsis, LogOut } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { logOut } from "@/actions/auth";
import { AddIcon } from "@/components/icons";
import { CollapseMenuButton } from "@/components/ui/sidebar/collapse-menu-button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip/tooltip";
import { getMenuList } from "@/lib/menu-list";
import { cn } from "@/lib/utils";

import { Button } from "../button/button";
import { CustomButton } from "../custom/custom-button";
import { ScrollArea } from "../scroll-area/scroll-area";

export const Menu = ({ isOpen }: { isOpen: boolean }) => {
  const pathname = usePathname();
  const menuList = getMenuList(pathname);

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
          <ul className="flex min-h-[calc(100vh-16px-60px-40px-16px-32px-40px-32px)] flex-col items-start space-y-1 px-2 lg:min-h-[calc(100vh-16px-60px-40px-16px-64px-16px)]">
            {menuList.map(({ groupLabel, menus }, index) => (
              <li
                className={cn(
                  "w-full",
                  groupLabel ? "pt-2" : "",
                  "last:!mt-auto",
                )}
                key={index}
              >
                {(isOpen && groupLabel) || isOpen === undefined ? (
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
                {menus.map(
                  (
                    { href, label, icon: Icon, active, submenus, defaultOpen },
                    index,
                  ) =>
                    !submenus || submenus.length === 0 ? (
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
                                <Link href={href}>
                                  <span
                                    className={cn(
                                      isOpen === false ? "" : "mr-4",
                                    )}
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
                            {isOpen === false && (
                              <TooltipContent side="right">
                                {label}
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
                    ),
                )}
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
    </>
  );
};
