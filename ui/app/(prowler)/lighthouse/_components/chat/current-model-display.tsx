import type { LighthouseV2ProviderType } from "@/app/(prowler)/lighthouse/_types";

import { ProviderIcon } from "../config/provider-icon";

interface CurrentModelDisplayProps {
  provider: LighthouseV2ProviderType;
  providerName: string;
  modelName: string;
}

export function CurrentModelDisplay({
  provider,
  providerName,
  modelName,
}: CurrentModelDisplayProps) {
  return (
    <div
      aria-label={`Current model: ${providerName} ${modelName}`}
      className="border-border-neutral-secondary bg-bg-neutral-secondary flex h-8 max-w-48 min-w-0 items-center gap-2 overflow-hidden rounded-lg border px-2.5 text-sm"
    >
      <ProviderIcon
        provider={provider}
        className="text-text-neutral-secondary size-3.5 shrink-0"
      />
      <span className="text-text-neutral-tertiary shrink-0">
        {providerName}
      </span>
      <span className="text-text-neutral-primary min-w-0 truncate font-medium">
        {modelName}
      </span>
    </div>
  );
}
