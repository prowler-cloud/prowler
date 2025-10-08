"use client";

import { CustomButton } from "@/components/ui/custom";

interface TableLinkProps {
  href: string;
  label: string;
  isDisabled?: boolean;
}

export const TableLink = ({ href, label, isDisabled }: TableLinkProps) => {
  return (
    // TODO: Replace CustomButton with CustomLink once the CustomLink component is merged.
    <CustomButton
      asLink={href}
      ariaLabel={label}
      variant="ghost"
      className="text-default-500 hover:text-primary text-xs font-medium disabled:opacity-30"
      size="sm"
      isDisabled={isDisabled}
    >
      {label}
    </CustomButton>
  );
};

TableLink.displayName = "TableLink";
