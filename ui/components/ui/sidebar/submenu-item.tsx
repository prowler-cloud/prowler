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
import { IconComponent } from "@/types";

interface SubmenuItemProps {
  href: string;
  label: string;
  icon: IconComponent;
  active?: boolean;
  target?: string;
  disabled?: boolean;
  highlight?: boolean;
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
            className="pointer-events-none mt-1 w-[calc(100%-12px)] cursor-not-allowed justify-start py-1"
            disabled
          >
            <span className="mr-2">
              <Icon size={16} />
            </span>
            <p className="max-w-[170px] truncate">{label}</p>
          </Button>
        </TooltipTrigger>
        <TooltipContent side="right">
          The mutelist will be enabled after adding a provider
        </TooltipContent>
      </Tooltip>
    );
  }

  return (
    <Button
      variant={isActive ? "menu-active" : "menu-inactive"}
      className="mt-1 w-[calc(100%-12px)] justify-start py-1"
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
        <p className="flex max-w-[170px] items-center truncate">
          <span>{label}</span>
          {highlight && (
            <span className="ml-2 rounded-sm bg-emerald-500 px-1.5 py-0.5 text-[10px] font-semibold text-white">
              NEW
            </span>
          )}
        </p>
      </Link>
    </Button>
  );
};
