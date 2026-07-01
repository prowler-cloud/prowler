import { SearchX } from "lucide-react";
import Link from "next/link";
import { ReactNode } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Card,
  CardContent,
  CardFooter,
  CardTitle,
} from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

const SCORE_CONFIG = {
  FAIL: {
    textColor: "text-text-error-primary",
    minScore: 0,
    maxScore: 30,
  },
  WARNING: {
    textColor: "text-text-warning-primary",
    minScore: 31,
    maxScore: 60,
  },
  PASS: {
    textColor: "text-text-success-primary",
    minScore: 61,
    maxScore: 100,
  },
} as const;

const getScoreTextColor = (score: number): string => {
  for (const config of Object.values(SCORE_CONFIG)) {
    if (score >= config.minScore && score <= config.maxScore) {
      return config.textColor;
    }
  }

  return SCORE_CONFIG.WARNING.textColor;
};

const getFailureTextColor = (value: number): string => {
  return value === 0
    ? SCORE_CONFIG.PASS.textColor
    : SCORE_CONFIG.FAIL.textColor;
};

export interface WatchlistItem {
  icon?: ReactNode;
  label: string;
  key: string;
  value: string | number;
}

export interface WatchlistCardProps
  extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  items: WatchlistItem[];
  ctaLabel?: string;
  ctaHref?: string;
  headerAction?: React.ReactNode;
  emptyState?: {
    message?: string;
    description?: string;
    linkText?: string;
  };
  onItemClick?: (item: WatchlistItem) => void;
  /**
   * When true, uses failure-based coloring: green for 0, red otherwise.
   * When false (default), uses score-based coloring (0-30 red, 31-60 yellow, 61-100 green).
   */
  useFailureColoring?: boolean;
}

export const WatchlistCard = ({
  title,
  items,
  ctaLabel,
  ctaHref,
  headerAction,
  emptyState,
  onItemClick,
  useFailureColoring = false,
}: WatchlistCardProps) => {
  const isEmpty = items.length === 0;

  return (
    <Card
      variant="base"
      className="flex min-h-[405px] w-full flex-col overflow-hidden"
    >
      <div className="flex items-center justify-between">
        <CardTitle>{title}</CardTitle>
        {headerAction}
      </div>
      <CardContent className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {isEmpty ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-12 py-6">
            {/* Icon and message */}
            <div className="flex flex-col items-center gap-6 pb-[18px]">
              <SearchX size={64} className="text-bg-data-muted" />
              <p className="text-text-neutral-tertiary w-full text-center text-sm leading-6">
                {emptyState?.message || "This space is looking empty."}
              </p>
            </div>

            {/* Description with link */}
            {emptyState?.description && ctaHref && (
              <p className="text-text-neutral-tertiary w-full text-sm leading-6">
                Visit the{" "}
                <Button variant="link" size="link-sm" asChild>
                  <Link href={ctaHref}>{emptyState.linkText || ctaLabel}</Link>
                </Button>{" "}
                {emptyState.description}
              </p>
            )}
          </div>
        ) : (
          <>
            {items.map((item, index) => {
              const isLast = index === items.length - 1;

              // Parse numeric value if it's a percentage string (e.g., "10%")
              const numericValue =
                typeof item.value === "string"
                  ? parseFloat(item.value.replace("%", ""))
                  : item.value;

              // Get color based on score or failure count
              const valueColorClass = !isNaN(numericValue)
                ? useFailureColoring
                  ? getFailureTextColor(numericValue)
                  : getScoreTextColor(numericValue)
                : "text-text-neutral-tertiary";

              const isClickable = !!onItemClick;

              return (
                <div
                  key={item.key}
                  role={isClickable ? "button" : undefined}
                  tabIndex={isClickable ? 0 : undefined}
                  onClick={() => onItemClick?.(item)}
                  onKeyDown={(e) => {
                    if (isClickable && (e.key === "Enter" || e.key === " ")) {
                      e.preventDefault();
                      onItemClick?.(item);
                    }
                  }}
                  className={cn(
                    "flex h-[54px] min-w-0 items-center justify-between gap-2 px-3 py-[11px]",
                    !isLast && "border-border-neutral-tertiary border-b",
                    isClickable &&
                      "hover:bg-bg-neutral-tertiary cursor-pointer",
                  )}
                >
                  {item.icon && (
                    <div className="flex size-6 shrink-0 items-center justify-center overflow-hidden rounded-md bg-white">
                      {item.icon}
                    </div>
                  )}

                  <p className="text-text-neutral-secondary w-0 flex-1 truncate text-sm leading-6">
                    {item.label}
                  </p>
                  <div className="flex shrink-0 items-center gap-1.5">
                    <p
                      className={cn(
                        "text-sm leading-6 font-bold",
                        valueColorClass,
                      )}
                    >
                      {item.value}
                    </p>
                  </div>
                </div>
              );
            })}
          </>
        )}
      </CardContent>

      {ctaLabel && ctaHref && (
        <CardFooter className="mb-6">
          <Button variant="link" size="link-sm" asChild className="w-full">
            <Link href={ctaHref}>{ctaLabel}</Link>
          </Button>
        </CardFooter>
      )}
    </Card>
  );
};
