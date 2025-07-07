import clsx from "clsx";
import Link from "next/link";
import React from "react";

interface CustomLinkProps
  extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  path: string;
  target?: "_self" | "_blank";
  rel?: string;
  className?: string;
  children?: React.ReactNode;
  variant?:
    | "default"
    | "dashed"
    | "underline"
    | "ghost"
    | "block"
    | "solid"
    | "unstyled";
  color?:
    | "primary"
    | "secondary"
    | "action"
    | "transparent"
    | "danger"
    | "success"
    | "muted";
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
  dashed: "border border-dashed border-current",
  underline: "underline hover:opacity-80",
  ghost: "bg-transparent text-inherit",
  block: "block w-full text-left",
  unstyled: "",
  solid: "rounded-md px-4 py-2 !font-bold",
};

const colorClasses = {
  primary: "text-prowler-theme-green",
  secondary: "text-default-800 dark:text-white",
  action: "bg-prowler-theme-green font-bold text-prowler-theme-midnight ",
  transparent: "border-0 border-transparent bg-transparent",
  danger: "text-red-600 dark:text-red-400",
  success: "text-green-600 dark:text-green-400",
  muted: "text-gray-500 dark:text-gray-400",
};

export const CustomLink = React.forwardRef<HTMLAnchorElement, CustomLinkProps>(
  (
    {
      path,
      target = "_self",
      rel,
      className,
      children,
      variant = "default",
      color = "primary",
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

    const combinedClasses = clsx(
      linkClasses.base,
      colorClasses[color],
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
        href={path}
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
