import type { ReactNode } from "react";

interface RegistryArtifactGridProps {
  children: ReactNode;
  emptyMessage: string;
  isEmpty: boolean;
}

export function RegistryArtifactGrid({
  children,
  emptyMessage,
  isEmpty,
}: RegistryArtifactGridProps) {
  if (isEmpty) {
    return (
      <p className="text-text-neutral-secondary text-sm">{emptyMessage}</p>
    );
  }

  return (
    <ul className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      {children}
    </ul>
  );
}
