import { Icon } from "@iconify/react";

import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";

const LIGHTHOUSE_V2_PROVIDER_ICONS = {
  [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI]: "simple-icons:openai",
  [LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK]: "simple-icons:amazonwebservices",
  [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE]: "simple-icons:openai",
} as const satisfies Record<LighthouseV2ProviderType, string>;

export function ProviderIcon({
  provider,
  className,
}: {
  provider: LighthouseV2ProviderType;
  className?: string;
}) {
  return (
    <Icon
      aria-hidden="true"
      className={className}
      icon={LIGHTHOUSE_V2_PROVIDER_ICONS[provider]}
    />
  );
}
