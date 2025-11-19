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
      <Button variant="link" size="sm" disabled className="text-xs">
        {label}
      </Button>
    );
  }

  return (
    <Button asChild variant="link" size="sm" className="text-xs">
      <Link href={href}>{label}</Link>
    </Button>
  );
};

TableLink.displayName = "TableLink";
