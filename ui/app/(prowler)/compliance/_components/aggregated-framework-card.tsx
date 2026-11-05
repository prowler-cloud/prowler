import Image from "next/image";
import type { ReactNode } from "react";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Card, CardAction, CardContent } from "@/components/shadcn/card/card";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

interface AggregatedFrameworkCardProps {
  frameworkTitle: string;
  formattedTitle: string;
  ariaLabel: string;
  onActivate: () => void;
  subtitle: ReactNode;
  tooltip?: string;
  actions?: ReactNode;
  children: ReactNode;
}

export const AggregatedFrameworkCard = ({
  frameworkTitle,
  formattedTitle,
  ariaLabel,
  onActivate,
  subtitle,
  tooltip,
  actions,
  children,
}: AggregatedFrameworkCardProps) => {
  const logo = getComplianceIcon(frameworkTitle);
  const title = (
    <h4 className="truncate text-sm leading-5 font-bold">{formattedTitle}</h4>
  );

  return (
    <Card variant="base" padding="none" interactive className="relative">
      <button
        type="button"
        aria-label={ariaLabel}
        onClick={onActivate}
        className="focus-visible:ring-border-neutral-secondary/50 w-full rounded-xl bg-transparent px-4 py-3 text-left outline-none focus-visible:ring-2"
      >
        <CardContent>
          <div className="flex w-full flex-col gap-3">
            <div className={cn("flex items-center gap-3", actions && "pr-8")}>
              {logo && (
                <div className="border-border-neutral-tertiary flex h-10 w-10 min-w-10 shrink-0 items-center justify-center rounded-md border bg-slate-50">
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
      </button>
      {actions && (
        <CardAction className="absolute top-2 right-2 z-10">
          {actions}
        </CardAction>
      )}
    </Card>
  );
};
