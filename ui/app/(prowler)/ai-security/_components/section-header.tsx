import type { ReactNode } from "react";

import { CardHeader, CardTitle } from "@/components/shadcn";

interface SectionHeaderProps {
  title: string;
  description: string;
  /** A link or legend on the right of the title. */
  aside?: ReactNode;
}

/** Title, one line on how to read the card, and what sits beside them. */
export const SectionHeader = ({
  title,
  description,
  aside,
}: SectionHeaderProps) => (
  <CardHeader className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
    <div className="flex flex-col gap-2">
      <CardTitle>{title}</CardTitle>
      <p className="text-text-neutral-tertiary text-xs">{description}</p>
    </div>
    {aside}
  </CardHeader>
);
