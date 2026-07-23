import Image from "next/image";
import type { KeyboardEventHandler, ReactNode } from "react";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Card, CardContent } from "@/components/shadcn/card/card";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

interface AggregatedFrameworkCardProps {
  frameworkTitle: string;
  formattedTitle: string;
  ariaLabel: string;
  onActivate: () => void;
  subtitle: ReactNode;
  tooltip?: string;
  children: ReactNode;
}

export const AggregatedFrameworkCard = ({
  frameworkTitle,
  formattedTitle,
  ariaLabel,
  onActivate,
  subtitle,
  tooltip,
  children,
}: AggregatedFrameworkCardProps) => {
  const handleKeyDown: KeyboardEventHandler<HTMLDivElement> = (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onActivate();
    }
  };
  const logo = getComplianceIcon(frameworkTitle);
  const title = (
    <h4 className="truncate text-sm leading-5 font-bold">{formattedTitle}</h4>
  );

  return (
    <Card
      variant="base"
      padding="md"
      interactive
      onClick={onActivate}
      role="button"
      aria-label={ariaLabel}
      tabIndex={0}
      onKeyDown={handleKeyDown}
    >
      <CardContent>
        <div className="flex w-full flex-col gap-3">
          <div className="flex items-center gap-3">
            {logo && (
              <div className="border-border-neutral-tertiary flex h-10 w-10 min-w-10 shrink-0 items-center justify-center rounded-md border bg-gray-50">
                <Image
                  src={logo}
                  alt={`${frameworkTitle} logo`}
                  width={32}
                  height={32}
                  sizes="32px"
                  className="h-8 w-8 object-contain"
                />
              </div>
            )}
            <div className="flex min-w-0 flex-1 flex-col">
              {tooltip ? (
                <Tooltip>
                  <TooltipTrigger asChild>{title}</TooltipTrigger>
                  <TooltipContent>{tooltip}</TooltipContent>
                </Tooltip>
              ) : (
                title
              )}
              {subtitle}
            </div>
          </div>
          {children}
        </div>
      </CardContent>
    </Card>
  );
};
