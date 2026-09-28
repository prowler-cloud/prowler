import { PackageSearch } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";

interface RegistryArtifactGridProps {
  children: ReactNode;
  emptyMessage: string;
  isEmpty: boolean;
  emptyDescription?: string;
  emptyActionLabel?: string;
  onReset?: () => void;
}

export function RegistryArtifactGrid({
  children,
  emptyMessage,
  isEmpty,
  onReset,
  emptyDescription = "Try another search or clear your filters to explore the catalog.",
  emptyActionLabel = "Clear filters",
}: RegistryArtifactGridProps) {
  if (isEmpty)
    return (
      <Card variant="base">
        <CardContent className="flex flex-col items-center gap-4 py-12 text-center">
          <PackageSearch
            aria-hidden
            className="text-text-neutral-secondary size-10"
          />
          <h2 className="text-text-neutral-primary text-lg font-semibold">
            {emptyMessage}
          </h2>
          <p className="text-text-neutral-secondary max-w-prose text-sm">
            {emptyDescription}
          </p>
          {onReset && (
            <Button variant="outline" onClick={onReset}>
              {emptyActionLabel}
            </Button>
          )}
        </CardContent>
      </Card>
    );
  return (
    <ul className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      {children}
    </ul>
  );
}
