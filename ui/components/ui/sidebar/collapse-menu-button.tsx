"use client";

import { Tooltip } from "@nextui-org/react";
import { DropdownMenuArrow } from "@radix-ui/react-dropdown-menu";
import { ChevronDown } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible/collapsible";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu/dropdown-menu";
import { cn } from "@/lib/utils";
import { CollapseMenuButtonProps } from "@/types";

import { Button } from "../button/button";

export const CollapseMenuButton = ({
  icon: Icon,
  label,
  submenus,
  defaultOpen,
  isOpen,
}: CollapseMenuButtonProps) => {
  const pathname = usePathname();
  const isSubmenuActive = submenus.some((submenu) =>
    submenu.active === undefined ? submenu.href === pathname : submenu.active,
  );
  const [isCollapsed, setIsCollapsed] = useState<boolean>(
    isSubmenuActive || defaultOpen,
  );

  return isOpen ? (
    <Collapsible
      open={isCollapsed}
      onOpenChange={setIsCollapsed}
      defaultOpen={defaultOpen}
      className="w-full"
    >
      <CollapsibleTrigger
        className="[&[data-state=open]>div>div>svg]:rotate-180"
        asChild
      >
        <Button
          variant={isSubmenuActive ? "secondary" : "ghost"}
          className="mb-1 h-7 w-full justify-start"
        >
          <div className="flex w-full items-center justify-between">
            <div className="flex items-center">
              <span className="mr-4">
                <Icon size={18} />
              </span>
              <p
                className={cn(
                  "max-w-[150px] truncate",
                  isOpen
                    ? "translate-x-0 opacity-100"
                    : "-translate-x-96 opacity-0",
                )}
              >
                {label}
              </p>
            </div>
            <div
              className={cn(
                "whitespace-nowrap",
                isOpen
                  ? "translate-x-0 opacity-100"
                  : "-translate-x-96 opacity-0",
              )}
            >
              <ChevronDown
                size={18}
                className="transition-transform duration-200"
              />
            </div>
          </div>
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down">
        {submenus.map(
          ({ href, label, active, icon: SubIcon, target, disabled }, index) => {
            const isActive =
              (active === undefined && pathname === href) || active;

            if (disabled && label === "Mutelist") {
              return (
                <Tooltip
                  key={index}
                  content="The mutelist will be enabled after adding a provider"
                  className="text-xs"
                  placement="right"
                >
                  <div className="w-full">
                    <Button
                      variant={isActive ? "secondary" : "ghost"}
                      className={cn(
                        "ml-4 h-8 w-full justify-start",
                        "cursor-not-allowed opacity-50",
                      )}
                      disabled={true}
                    >
                      <div className="flex items-center">
                        <div className="mr-4 h-full border-l border-default-200"></div>
                        <span className="mr-2">
                          <SubIcon size={16} />
                        </span>
                        <p
                          className={cn(
                            "max-w-[170px] truncate",
                            isOpen
                              ? "translate-x-0 opacity-100"
                              : "-translate-x-96 opacity-0",
                          )}
                        >
                          {label}
                        </p>
                      </div>
                    </Button>
                  </div>
                </Tooltip>
              );
            }

            return (
              <Button
                key={index}
                variant={isActive ? "secondary" : "ghost"}
                className={cn(
                  "ml-4 h-8 w-full justify-start",
                  disabled && "cursor-not-allowed opacity-50",
                )}
                asChild={!disabled}
                disabled={disabled}
              >
                <Link href={href} target={target} className="flex items-center">
                  <div className="mr-4 h-full border-l border-default-200"></div>
                  <span className="mr-2">
                    <SubIcon size={16} />
                  </span>
                  <p
                    className={cn(
                      "max-w-[170px] truncate",
                      isOpen
                        ? "translate-x-0 opacity-100"
                        : "-translate-x-96 opacity-0",
                    )}
                  >
                    {label}
                  </p>
                </Link>
              </Button>
            );
          },
        )}
      </CollapsibleContent>
    </Collapsible>
  ) : (
    <DropdownMenu>
      <Tooltip
        content={label}
        placement="right"
        delay={100}
        className="text-xs"
      >
        <DropdownMenuTrigger asChild>
          <Button
            variant={isSubmenuActive ? "secondary" : "ghost"}
            className="mb-1 h-10 w-full justify-start"
          >
            <div className="flex w-full items-center justify-between">
              <div className="flex items-center">
                <span className={cn(isOpen === false ? "" : "mr-4")}>
                  <Icon size={18} />
                </span>
                <p
                  className={cn(
                    "max-w-[200px] truncate",
                    isOpen === false ? "opacity-0" : "opacity-100",
                  )}
                >
                  {label}
                </p>
              </div>
            </div>
          </Button>
        </DropdownMenuTrigger>
      </Tooltip>
      <DropdownMenuContent side="right" sideOffset={25} align="start">
        <DropdownMenuLabel className="max-w-[190px] truncate">
          {label}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {submenus.map(
          ({ href, label, active, icon: SubIcon, disabled }, index) => {
            const isActive =
              (active === undefined && pathname === href) || active;

            if (disabled && label === "Mutelist") {
              return (
                <Tooltip
                  key={index}
                  content="The mutelist will be enabled after adding a provider"
                  className="text-xs"
                >
                  <div className="w-full">
                    <DropdownMenuItem
                      disabled={true}
                      className={cn(
                        "cursor-not-allowed opacity-50",
                        isActive && "bg-default-100 dark:bg-prowler-blue-400",
                      )}
                    >
                      <div className="flex items-center gap-2">
                        <SubIcon size={16} />
                        <p className="max-w-[180px] truncate">{label}</p>
                      </div>
                    </DropdownMenuItem>
                  </div>
                </Tooltip>
              );
            }

            return (
              <DropdownMenuItem
                key={index}
                asChild={!disabled}
                disabled={disabled}
                className={cn(
                  disabled && "cursor-not-allowed opacity-50",
                  isActive && "bg-default-100 dark:bg-prowler-blue-400",
                )}
              >
                {disabled ? (
                  <div className="flex items-center gap-2">
                    <SubIcon size={16} />
                    <p className="max-w-[180px] truncate">{label}</p>
                  </div>
                ) : (
                  <Link
                    className="flex cursor-pointer items-center gap-2"
                    href={href}
                  >
                    <SubIcon size={16} />
                    <p className="max-w-[180px] truncate">{label}</p>
                  </Link>
                )}
              </DropdownMenuItem>
            );
          },
        )}
        <DropdownMenuArrow className="fill-border" />
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
