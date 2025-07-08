import Link from "next/link";
import React from "react";

import { cn } from "@/lib";

interface CustomLinkProps
  extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string;
  target?: "_self" | "_blank";
  rel?: string;
  className?: string;
  children?: React.ReactNode;
  variant?:
    | "default"
    | "dashed"
    | "ghost"
    | "block"
    | "solid"
    | "unstyled"
    | "iconButton"
    | "textLink";
  color?:
    | "primary"
    | "secondary"
    | "action"
    | "transparent"
    | "danger"
    | "success"
    | "muted";
  size?: "md" | "sm" | "lg";
  startContent?: React.ReactNode;
  endContent?: React.ReactNode;
  isIconOnly?: boolean;
  ariaLabel?: string;
  isDisabled?: boolean;
}

const linkClasses = {
  base: "inline-flex items-center gap-1 text-sm font-medium transition-colors duration-200",
  iconOnly: "p-2 rounded-full justify-center",
  disabled: "opacity-30 pointer-events-none cursor-not-allowed",
};

const variantClasses = {
  default: "",
  dashed:
    "border border-default border-dashed bg-transparent  justify-center whitespace-nowrap shadow-sm hover:border-solid hover:bg-default-100 active:bg-default-200 active:border-solid",
  iconButton:
    "whitespace-nowrap rounded-[14px] border-2 border-gray-200 bg-prowler-grey-medium p-3 bg-transparent",
  ghost:
    "whitespace-nowrap border border-prowler-theme-green text-default-500 hover:bg-prowler-theme-green hover:!text-black disabled:opacity-30",
  solid: "whitespace-nowrap min-w-20",
  textLink: "h-auto w-fit min-w-0 p-0 text-blue-500",
  block: "block w-full text-left",
  unstyled: "",
};

const colorClasses = {
  primary: "text-prowler-theme-green",
  secondary: "text-default-800 dark:text-white",
  action:
    "bg-prowler-theme-green font-bold text-prowler-theme-midnight hover:opacity-80 transition-opacity duration-100",
  transparent: "border-0 border-transparent bg-transparent",
  danger: "text-red-600 dark:text-red-400",
  success: "text-green-600 dark:text-green-400",
  muted: "text-gray-500 dark:text-gray-400",
};

const sizeClasses = {
  sm: "text-xs px-4 h-8 rounded-lg",
  md: "text-sm px-4 py-2 h-10 rounded-lg",
  lg: "text-lg px-5 py-3 h-12 rounded-xl",
};

export const CustomLink = React.forwardRef<HTMLAnchorElement, CustomLinkProps>(
  (
    {
      href,
      target = "_self",
      rel,
      className,
      children,
      variant = "default",
      color = "primary",
      size = "md",
      startContent,
      endContent,
      isIconOnly = false,
      ariaLabel,
      isDisabled = false,
      ...rest
    },
    ref,
  ) => {
    const isExternal = target === "_blank";
    const computedRel = isExternal ? "noopener noreferrer" : rel;

    const content = (
      <>
        {startContent && <span>{startContent}</span>}
        {!isIconOnly && children}
        {endContent && <span>{endContent}</span>}
      </>
    );

    const combinedClasses = cn(
      linkClasses.base,
      colorClasses[color],
      sizeClasses[size],
      variantClasses[variant],
      isIconOnly && linkClasses.iconOnly,
      isDisabled && linkClasses.disabled,
      className,
    );

    return isDisabled ? (
      <span
        className={combinedClasses}
        aria-disabled="true"
        aria-label={ariaLabel}
      >
        {content}
      </span>
    ) : (
      <Link
        href={href}
        target={target}
        rel={computedRel}
        ref={ref}
        aria-label={ariaLabel}
        className={combinedClasses}
        {...rest}
      >
        {content}
      </Link>
    );
  },
);

CustomLink.displayName = "CustomLink";
