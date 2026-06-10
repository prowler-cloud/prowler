"use client";

import { Icon } from "@iconify/react";

import { Card, CardContent, type CardProps } from "@/components/shadcn";
import { cn } from "@/lib";

const COLOR_STYLES = {
  success: {
    card: "border-system-success-medium",
    iconWrapper: "bg-system-success-lighter border-system-success",
    icon: "text-system-success",
  },
  secondary: {
    card: "border-secondary-100",
    iconWrapper: "bg-secondary-50 border-secondary-100",
    icon: "text-secondary",
  },
  warning: {
    card: "border-warning-500",
    iconWrapper: "bg-warning-50 border-warning-100",
    icon: "text-warning-600",
  },
  fail: {
    card: "border-danger-300",
    iconWrapper: "bg-danger-50 border-danger-100",
    icon: "text-text-error",
  },
  default: {
    card: "border-default-200",
    iconWrapper: "bg-default-50 border-default-100",
    icon: "text-default-500",
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
        "border-small",
        colors.card,
        className,
      )}
      {...props}
    >
      <CardContent className="flex h-full flex-row items-center gap-2 p-2">
        <div
          className={cn(
            "item-center rounded-medium flex border p-1",
            colors.iconWrapper,
          )}
        >
          <Icon className={colors.icon} icon={icon} width={24} />
        </div>
        <div className="flex flex-col">
          <p className="text-md">{title}</p>
          <p className="text-default-400 text-sm">{description || children}</p>
        </div>
      </CardContent>
    </Card>
  );
};
