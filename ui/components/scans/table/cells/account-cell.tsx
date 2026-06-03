"use client";

import { EntityInfo } from "@/components/ui/entities";
import type { ProviderType, ScanProps } from "@/types";

export function AccountCell({ scan }: { scan: ScanProps }) {
  const providerInfo = scan.providerInfo;

  if (!providerInfo) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  return (
    <div className="max-w-[240px] min-w-0">
      <EntityInfo
        cloudProvider={providerInfo.provider as ProviderType}
        entityAlias={providerInfo.alias}
        entityId={providerInfo.uid}
      />
    </div>
  );
}
