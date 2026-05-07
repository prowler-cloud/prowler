import type { CSSProperties } from "react";

import { cn } from "@/lib/utils";

interface MenuFeatureBadgeProps {
  label?: string;
  variant?: "cloud" | "new";
  size?: "default" | "sm";
  className?: string;
}

const FEATURE_BADGE_STYLE: Record<
  NonNullable<MenuFeatureBadgeProps["variant"]>,
  CSSProperties | undefined
> = {
  cloud: {
    backgroundImage:
      "linear-gradient(112deg, rgb(46, 229, 155) 3.5%, rgb(98, 223, 240) 98.8%)",
  },
  new: undefined,
};

const FEATURE_BADGE_VARIANT_CLASS: Record<
  NonNullable<MenuFeatureBadgeProps["variant"]>,
  string
> = {
  cloud: "text-primary-foreground",
  new: "bg-emerald-500 text-white",
};

const FEATURE_BADGE_SIZE_CLASS: Record<
  NonNullable<MenuFeatureBadgeProps["size"]>,
  string
> = {
  default: "h-6 rounded-lg px-2 text-xs leading-5",
  sm: "h-5 rounded-md px-1.5 text-[10px] leading-4",
};

export const MenuFeatureBadge = ({
  label,
  variant = "cloud",
  size = "default",
  className,
}: MenuFeatureBadgeProps) => (
  <span
    className={cn(
      "inline-flex shrink-0 items-center justify-center font-bold",
      FEATURE_BADGE_VARIANT_CLASS[variant],
      FEATURE_BADGE_SIZE_CLASS[size],
      className,
    )}
    style={FEATURE_BADGE_STYLE[variant]}
  >
    {label}
  </span>
);

export const CloudFeatureBadge = ({
  label = "Available in Prowler Cloud",
  size,
  className,
}: Omit<MenuFeatureBadgeProps, "variant">) => (
  <MenuFeatureBadge
    label={label}
    variant="cloud"
    size={size}
    className={className}
  />
);
