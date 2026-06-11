"use client";

import { Icon } from "@iconify/react";

import {
  Card,
  CardContent,
  type CardProps,
} from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

const COLOR_STYLES = {
  success: {
    card: "border-system-success-medium",
    iconWrapper: "bg-system-success-lighter border-system-success",
    icon: "text-system-success",
  },
  secondary: {
    card: "border-violet-200 dark:border-violet-950",
    iconWrapper:
      "bg-violet-50 dark:bg-violet-950 border-violet-200 dark:border-violet-900",
    icon: "text-violet-600 dark:text-violet-400",
  },
  warning: {
    card: "border-amber-500 dark:border-amber-400",
    iconWrapper:
      "bg-bg-warning-secondary border-amber-100 dark:border-amber-900",
    icon: "text-text-warning-primary",
  },
  fail: {
    card: "border-rose-400 dark:border-rose-700",
    iconWrapper: "bg-bg-fail-secondary border-rose-200 dark:border-rose-900",
    icon: "text-text-error",
  },
  default: {
    card: "border-border-neutral-secondary",
    iconWrapper: "bg-bg-neutral-tertiary border-border-neutral-secondary",
    icon: "text-text-neutral-tertiary",
  },
} as const;

export type ActionCardProps = CardProps & {
  icon: string;
  title: string;
  color?: "success" | "secondary" | "warning" | "fail";
  description: string;
};

export const ActionCard = ({
  color,
  title,
  icon,
  description,
  children,
  className,
  ...props
}: ActionCardProps) => {
  const colors = COLOR_STYLES[color ?? "default"];

  return (
    <Card
      role="button"
      tabIndex={0}
      className={cn(
        "bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary cursor-pointer gap-0 shadow-sm transition-colors",
        "border",
        colors.card,
        className,
      )}
      {...props}
    >
      <CardContent className="flex h-full flex-row items-center gap-2 p-2">
        <div
          className={cn(
            "item-center flex rounded-xl border p-1",
            colors.iconWrapper,
          )}
        >
          <Icon className={colors.icon} icon={icon} width={24} />
        </div>
        <div className="flex flex-col">
          <p className="text-md">{title}</p>
          <p className="text-text-neutral-tertiary text-sm">
            {description || children}
          </p>
        </div>
      </CardContent>
    </Card>
  );
};
