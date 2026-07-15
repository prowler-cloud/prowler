"use client";

import { ChevronDown } from "lucide-react";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { SubmenuItem } from "@/components/layout/sidebar/submenu-item";
import { Button } from "@/components/shadcn/button/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import {
  IconComponent,
  type MenuSelectionHandler,
  SUBMENU_KIND,
  SubmenuProps,
} from "@/types";

interface CollapsibleMenuProps {
  icon: IconComponent;
  label: string;
  submenus: SubmenuProps[];
  defaultOpen?: boolean;
  isOpen: boolean;
  onSelect?: MenuSelectionHandler;
}

export const CollapsibleMenu = ({
  icon: Icon,
  label,
  submenus,
  defaultOpen = false,
  isOpen: isSidebarOpen,
  onSelect,
}: CollapsibleMenuProps) => {
  const pathname = usePathname();
  const isSubmenuActive = submenus.some(
    (submenu) =>
      submenu.kind !== SUBMENU_KIND.CLOUD_UPGRADE &&
      (submenu.active === undefined
        ? submenu.href === pathname
        : submenu.active),
  );
  const [isCollapsed, setIsCollapsed] = useState(
    isSubmenuActive || defaultOpen,
  );
  const isOpen = isSidebarOpen && isCollapsed;

  return (
    <Collapsible
      open={isOpen}
      onOpenChange={setIsCollapsed}
      defaultOpen={defaultOpen}
      className="group mb-1 w-full"
    >
      <Tooltip delayDuration={100}>
        <TooltipTrigger asChild>
          <CollapsibleTrigger asChild>
            <Button
              variant={isSubmenuActive ? "menu-active" : "menu-inactive"}
              className={cn(
                isSidebarOpen ? "w-full justify-start" : "w-14 justify-center",
              )}
            >
              {isSidebarOpen ? (
                <div className="flex w-full items-center justify-between">
                  <div className="flex items-center">
                    <span className="mr-4">
                      <Icon size={18} />
                    </span>
                    <p className="max-w-[150px] truncate">{label}</p>
                  </div>
                  <ChevronDown
                    size={18}
                    className="transition-transform duration-200 group-data-[state=open]:rotate-180"
                  />
                </div>
              ) : (
                <Icon size={18} />
              )}
            </Button>
          </CollapsibleTrigger>
        </TooltipTrigger>
        {!isSidebarOpen && (
          <TooltipContent side="right">{label}</TooltipContent>
        )}
      </Tooltip>
      <CollapsibleContent className="data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down flex flex-col items-end overflow-hidden">
        {submenus.map((submenu, index) => (
          <SubmenuItem key={index} {...submenu} onSelect={onSelect} />
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
};
