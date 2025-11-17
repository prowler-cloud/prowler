"use client";

import { Tooltip } from "@heroui/tooltip";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { type MouseEvent } from "react";

import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";
import { IconComponent } from "@/types";

interface SubmenuItemProps {
  href: string;
  label: string;
  icon: IconComponent;
  active?: boolean;
  target?: string;
  disabled?: boolean;
  onClick?: (event: MouseEvent<HTMLAnchorElement>) => void;
}

export const SubmenuItem = ({
  href,
  label,
  icon: Icon,
  active,
  target,
  disabled,
  onClick,
}: SubmenuItemProps) => {
  const pathname = usePathname();
  const isActive = active !== undefined ? active : pathname === href;

  // Special case: Mutelist with tooltip when disabled
  if (disabled && label === "Mutelist") {
    return (
      <Tooltip
        content="The mutelist will be enabled after adding a provider"
        className="text-xs"
        placement="right"
      >
        <div className="w-full">
          <Button
            variant={isActive ? "secondary" : "ghost"}
            className="ml-3 h-auto w-[calc(100%-12px)] cursor-not-allowed justify-start py-1 opacity-50"
            disabled
          >
            <div className="flex items-center">
              <div className="border-default-200 mr-4 h-full border-l" />
              <span className="mr-2">
                <Icon size={16} />
              </span>
              <p className="max-w-[170px] truncate">{label}</p>
            </div>
          </Button>
        </div>
      </Tooltip>
    );
  }

  return (
    <Button
      variant={isActive ? "secondary" : "ghost"}
      className={cn(
        "ml-3 h-auto w-[calc(100%-12px)] justify-start py-1",
        disabled && "cursor-not-allowed opacity-50",
      )}
      asChild={!disabled}
      disabled={disabled}
    >
      <Link
        href={href}
        target={target}
        className="flex items-center"
        onClick={onClick}
      >
        <div className="border-default-200 mr-4 h-full border-l" />
        <span className="mr-2">
          <Icon size={16} />
        </span>
        <p className="max-w-[170px] truncate">{label}</p>
      </Link>
    </Button>
  );
};
