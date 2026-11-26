import type { ReactNode } from "react";

interface RegistryArtifactGridProps {
  children: ReactNode;
}

export function RegistryArtifactGrid({ children }: RegistryArtifactGridProps) {
  return (
    <ul className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      {children}
    </ul>
  );
}
