"use client";

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

export const CustomLink = ({
  href,
  target = "_blank",
  ariaLabel,
  className,
  children,
  scroll = true,
  size = "xs",
  ...props
}: CustomLinkProps) => {
  return (
    <Link
      href={href}
      scroll={scroll}
      className={cn(`text-${size} font-medium text-primary`, className)}
      aria-label={ariaLabel}
      target={target}
      rel="noopener noreferrer"
      {...props}
    >
      {children}
    </Link>
  );
};

CustomLink.displayName = "CustomLink";
