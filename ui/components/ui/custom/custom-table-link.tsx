"use client";

import Link from "next/link";

import { Button } from "@/components/shadcn";

interface TableLinkProps {
  href: string;
  label: string;
  isDisabled?: boolean;
}

export const TableLink = ({ href, label, isDisabled }: TableLinkProps) => {
  if (isDisabled) {
    return (
      <span className="text-text-neutral-tertiary inline-flex h-9 cursor-not-allowed items-center justify-center px-3 text-xs font-medium opacity-60">
        {label}
      </span>
    );
  }

  return (
    <Button asChild variant="link" size="sm" className="text-xs">
      <Link href={href} prefetch={false}>
        {label}
      </Link>
    </Button>
  );
};

TableLink.displayName = "TableLink";
