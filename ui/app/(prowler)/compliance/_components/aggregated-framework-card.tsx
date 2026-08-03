import Image from "next/image";
import type { KeyboardEventHandler, ReactNode } from "react";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Card, CardContent } from "@/components/shadcn/card/card";
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
  /**
   * Controls that are not part of the card's own activation, e.g. the
   * watchlist toggle. Pinned to the card's top-right corner so they cost no
   * vertical room and every card in a grid keeps the same height; the slot's
   * contents are responsible for stopping event propagation, since the card
   * itself is a button.
   */
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
      className="relative"
    >
      {actions && <div className="absolute top-2 right-2 z-10">{actions}</div>}
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
    </Card>
  );
};
