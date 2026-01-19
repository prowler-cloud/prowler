"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
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
  highlight?: boolean;
}

export const MenuItem = ({
  href,
  label,
  icon: Icon,
  active,
  target,
  tooltip,
  isOpen,
  highlight,
}: MenuItemProps) => {
  const pathname = usePathname();
  const isActive = active !== undefined ? active : pathname.startsWith(href);

  // Show tooltip always for Prowler Hub, or when sidebar is collapsed
  const showTooltip = label === "Prowler Hub" ? !!tooltip : !isOpen;

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Button
          variant={isActive ? "menu-active" : "menu-inactive"}
          className={cn(
            isOpen ? "w-full justify-start" : "w-14 justify-center",
            highlight &&
              "relative overflow-hidden before:absolute before:inset-0 before:rounded-lg before:bg-gradient-to-r before:from-emerald-500/20 before:via-teal-400/20 before:to-emerald-300/20 before:opacity-70",
          )}
          asChild
        >
          <Link href={href} target={target}>
            <div className="relative z-10 flex items-center">
              <span
                className={cn(
                  isOpen ? "mr-4" : "",
                  highlight && "text-button-primary",
                )}
              >
                <Icon size={18} />
              </span>
              {isOpen && (
                <p className="max-w-[200px] truncate">
                  {label}
                  {highlight && (
                    <span className="ml-2 rounded-sm bg-emerald-500 px-1.5 py-0.5 text-[10px] font-semibold text-white">
                      NEW
                    </span>
                  )}
                </p>
              )}
            </div>
          </Link>
        </Button>
      </TooltipTrigger>
      {showTooltip && (
        <TooltipContent side="right">{tooltip || label}</TooltipContent>
      )}
    </Tooltip>
  );
};
