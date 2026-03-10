"use client";

import { InfoIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

import { Tooltip, TooltipContent, TooltipTrigger } from "../tooltip";

export const INFO_FIELD_VARIANTS = {
  default: "default",
  simple: "simple",
  transparent: "transparent",
} as const;

type InfoFieldVariant =
  (typeof INFO_FIELD_VARIANTS)[keyof typeof INFO_FIELD_VARIANTS];

interface InfoFieldProps {
  label: string;
  children: ReactNode;
  variant?: InfoFieldVariant;
  className?: string;
  tooltipContent?: string;
  inline?: boolean;
}

export function InfoField({
  label,
  children,
  variant = "default",
  tooltipContent,
  className,
  inline = false,
}: InfoFieldProps) {
  const labelContent = (
    <span className="flex items-center gap-1">
      {label}
      {inline && ":"}
      {tooltipContent && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="inline-flex cursor-pointer items-center">
              <InfoIcon className="text-bg-data-info size-3" />
            </span>
          </TooltipTrigger>
          <TooltipContent>{tooltipContent}</TooltipContent>
        </Tooltip>
      )}
    </span>
  );

  if (inline) {
    return (
      <div className={cn("flex items-center gap-2", className)}>
        <span className="text-text-neutral-tertiary text-xs font-bold">
          {labelContent}
        </span>
        <div className="text-text-neutral-primary text-sm">{children}</div>
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <span className="text-text-neutral-tertiary text-xs font-bold">
        {labelContent}
      </span>

      {variant === "simple" ? (
        <div className="text-text-neutral-primary text-sm break-all">
          {children}
        </div>
      ) : variant === "transparent" ? (
        <div className="text-text-neutral-primary text-sm">{children}</div>
      ) : (
        <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary text-text-neutral-primary rounded-lg border px-3 py-2 text-sm">
          {children}
        </div>
      )}
    </div>
  );
}
