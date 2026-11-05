import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";
import { AmazonWebServicesIcon, OpenAIIcon } from "@/components/icons/Icons";
import type { IconComponent } from "@/types/components";

const LIGHTHOUSE_V2_PROVIDER_ICONS = {
  [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI]: OpenAIIcon,
  [LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK]: AmazonWebServicesIcon,
  [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE]: OpenAIIcon,
} as const satisfies Record<LighthouseV2ProviderType, IconComponent>;

export function ProviderIcon({
  provider,
  className,
}: {
  provider: LighthouseV2ProviderType;
  className?: string;
}) {
  const Icon = LIGHTHOUSE_V2_PROVIDER_ICONS[provider];
  return <Icon aria-hidden="true" className={className} />;
}
