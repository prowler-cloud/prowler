import Link from "next/link";
import React from "react";

import { cn } from "@/lib";

interface CustomLinkProps
  extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string;
  target?: "_self" | "_blank" | string;
  ariaLabel?: string;
  className?: string;
  children: React.ReactNode;
  scroll?: boolean;
  size?: string;
}

export const CustomLink = React.forwardRef<HTMLAnchorElement, CustomLinkProps>(
  (
    {
      href,
      target = "_blank",
      ariaLabel,
      className,
      children,
      scroll = true,
      size = "xs",
      ...props
    },
    ref,
  ) => {
    return (
      <Link
        ref={ref}
        href={href}
        scroll={scroll}
        aria-label={ariaLabel}
        target={target}
        rel={target === "_blank" ? "noopener noreferrer" : undefined}
        className={cn(`text-${size} text-button-tertiary p-0`, className)}
        {...props}
      >
        {children}
      </Link>
    );
  },
);

CustomLink.displayName = "CustomLink";
