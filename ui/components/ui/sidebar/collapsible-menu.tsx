"use client";

import { ChevronDown } from "lucide-react";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible/collapsible";
import { SubmenuItem } from "@/components/ui/sidebar/submenu-item";
import { IconComponent, SubmenuProps } from "@/types";

interface CollapsibleMenuProps {
  icon: IconComponent;
  label: string;
  submenus: SubmenuProps[];
  defaultOpen?: boolean;
}

export const CollapsibleMenu = ({
  icon: Icon,
  label,
  submenus,
  defaultOpen = false,
}: CollapsibleMenuProps) => {
  const pathname = usePathname();
  const isSubmenuActive = submenus.some((submenu) =>
    submenu.active === undefined ? submenu.href === pathname : submenu.active,
  );
  const [isOpen, setIsOpen] = useState(isSubmenuActive || defaultOpen);

  return (
    <Collapsible
      open={isOpen}
      onOpenChange={setIsOpen}
      defaultOpen={defaultOpen}
      className="mb-1 w-full"
    >
      <CollapsibleTrigger
        className="[&[data-state=open]>div>div>svg]:rotate-180"
        asChild
      >
        <Button
          variant={isSubmenuActive ? "secondary" : "ghost"}
          className="h-auto w-full justify-start px-4 py-1"
        >
          <div className="flex w-full items-center justify-between">
            <div className="flex items-center">
              <span className="mr-4">
                <Icon size={18} />
              </span>
              <p className="max-w-[150px] truncate">{label}</p>
            </div>
            <ChevronDown
              size={18}
              className="transition-transform duration-200"
            />
          </div>
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down overflow-hidden">
        {submenus.map((submenu, index) => (
          <SubmenuItem key={index} {...submenu} />
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
};
