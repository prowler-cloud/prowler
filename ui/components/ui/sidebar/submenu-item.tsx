"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { type MouseEvent } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { MenuFeatureBadge } from "@/components/shared/cloud-feature-badge";
import { IconComponent } from "@/types";

interface SubmenuItemProps {
  href: string;
  label: string;
  icon: IconComponent;
  active?: boolean;
  target?: string;
  disabled?: boolean;
  highlight?: boolean;
  cloudOnly?: boolean;
  onClick?: (event: MouseEvent<HTMLAnchorElement>) => void;
}

export const SubmenuItem = ({
  href,
  label,
  icon: Icon,
  active,
  target,
  disabled,
  highlight,
  cloudOnly,
  onClick,
}: SubmenuItemProps) => {
  const pathname = usePathname();
  const isActive = active !== undefined ? active : pathname === href;

  // Special case: Mutelist with tooltip when disabled
  if (disabled && label === "Mutelist") {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            className="pointer-events-none mt-1 w-[calc(100%-12px)] cursor-not-allowed justify-start px-2 py-1"
            disabled
          >
            <span className="mr-2">
              <Icon size={16} />
            </span>
            <p className="min-w-0 truncate">{label}</p>
          </Button>
        </TooltipTrigger>
        <TooltipContent side="right">
          The mutelist will be enabled after adding a provider
        </TooltipContent>
      </Tooltip>
    );
  }

  if (disabled) {
    const tooltip = cloudOnly
      ? "Available in Prowler Cloud"
      : `${label} is unavailable.`;

    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className="group mt-1 inline-flex w-[calc(100%-12px)]"
            tabIndex={0}
          >
            <Button
              variant="menu-inactive"
              className="text-text-neutral-tertiary w-full cursor-not-allowed justify-start px-2 py-1"
              aria-disabled="true"
              tabIndex={-1}
              type="button"
            >
              <span className="mr-2">
                <Icon size={16} />
              </span>
              <p className="flex min-w-0 items-center gap-2">
                <span className="truncate">{label}</span>
                {highlight && (
                  <MenuFeatureBadge label="New" variant="new" size="sm" />
                )}
              </p>
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent side="right">{tooltip}</TooltipContent>
      </Tooltip>
    );
  }

  return (
    <Button
      variant={isActive ? "menu-active" : "menu-inactive"}
      className="mt-1 w-[calc(100%-12px)] justify-start px-2 py-1"
      asChild={!disabled}
      disabled={disabled}
    >
      <Link
        href={href}
        target={target}
        className="flex items-center"
        onClick={onClick}
      >
        <span className="mr-2">
          <Icon size={16} />
        </span>
        <p className="flex min-w-0 items-center">
          <span className="truncate">{label}</span>
          {highlight && (
            <MenuFeatureBadge
              label="New"
              variant="new"
              size="sm"
              className="ml-2"
            />
          )}
        </p>
      </Link>
    </Button>
  );
};
