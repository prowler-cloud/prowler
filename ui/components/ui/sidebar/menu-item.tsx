"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip/tooltip";
import { cn } from "@/lib/utils";
import { IconComponent } from "@/types";

interface MenuItemProps {
  href: string;
  label: string;
  icon: IconComponent;
  active?: boolean;
  target?: string;
  tooltip?: string;
  isOpen: boolean;
}

export const MenuItem = ({
  href,
  label,
  icon: Icon,
  active,
  target,
  tooltip,
  isOpen,
}: MenuItemProps) => {
  const pathname = usePathname();
  const isActive = active !== undefined ? active : pathname.startsWith(href);

  return (
    <TooltipProvider disableHoverableContent>
      <Tooltip delayDuration={100}>
        <TooltipTrigger asChild>
          <Button
            variant={isActive ? "secondary" : "ghost"}
            className={cn(
              "h-auto px-4 py-1",
              isOpen ? "w-full justify-start" : "w-14 justify-center",
            )}
            asChild
          >
            <Link href={href} target={target}>
              <div className="flex items-center">
                <span className={cn(isOpen ? "mr-4" : "")}>
                  <Icon size={18} />
                </span>
                {isOpen && <p className="max-w-[200px] truncate">{label}</p>}
              </div>
            </Link>
          </Button>
        </TooltipTrigger>
        {tooltip && <TooltipContent side="right">{tooltip}</TooltipContent>}
      </Tooltip>
    </TooltipProvider>
  );
};
