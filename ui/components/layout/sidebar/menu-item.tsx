"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { MenuFeatureBadge } from "@/components/shared/cloud-feature-badge";
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
  // Extract only the pathname from href (without query parameters) for comparison
  const hrefPathname = href.split("?")[0];
  const isActive =
    active !== undefined ? active : pathname.startsWith(hrefPathname);

  // Show tooltip always for Prowler Hub, or when sidebar is collapsed
  const showTooltip = label === "Prowler Hub" ? !!tooltip : !isOpen;

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Button
          variant={isActive ? "menu-active" : "menu-inactive"}
          className={cn(
            isOpen ? "w-full justify-start" : "w-14 justify-center",
          )}
          asChild
        >
          <Link href={href} target={target}>
            <div className="flex items-center">
              <span className={cn(isOpen ? "mr-4" : "")}>
                <Icon size={18} />
              </span>
              {isOpen && (
                <p className="flex max-w-[200px] items-center truncate">
                  <span>{label}</span>
                  {highlight && (
                    <MenuFeatureBadge
                      label="New"
                      variant="new"
                      size="sm"
                      className="ml-2"
                    />
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
