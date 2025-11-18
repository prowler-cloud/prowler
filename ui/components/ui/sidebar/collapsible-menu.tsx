"use client";

import { ChevronDown } from "lucide-react";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible/collapsible";
import { SubmenuItem } from "@/components/ui/sidebar/submenu-item";
import { cn } from "@/lib/utils";
import { IconComponent, SubmenuProps } from "@/types";

interface CollapsibleMenuProps {
  icon: IconComponent;
  label: string;
  submenus: SubmenuProps[];
  defaultOpen?: boolean;
  isOpen: boolean;
}

export const CollapsibleMenu = ({
  icon: Icon,
  label,
  submenus,
  defaultOpen = false,
  isOpen: isSidebarOpen,
}: CollapsibleMenuProps) => {
  const pathname = usePathname();
  const isSubmenuActive = submenus.some((submenu) =>
    submenu.active === undefined ? submenu.href === pathname : submenu.active,
  );
  const [isCollapsed, setIsCollapsed] = useState(
    isSubmenuActive || defaultOpen,
  );

  // Collapse the menu when sidebar is closed
  useEffect(() => {
    if (!isSidebarOpen) {
      setIsCollapsed(false);
    }
  }, [isSidebarOpen]);

  return (
    <Collapsible
      open={isCollapsed}
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
          <SubmenuItem key={index} {...submenu} />
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
};
