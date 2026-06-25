import { Bot, Cloud, Server } from "lucide-react";

import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  type LighthouseV2ProviderType,
} from "@/app/(prowler)/lighthouse/_types";

function getProviderIcon(provider: LighthouseV2ProviderType) {
  if (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK) return Cloud;
  if (provider === LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE) return Server;
  return Bot;
}

export function ProviderIcon({
  provider,
  className,
}: {
  provider: LighthouseV2ProviderType;
  className?: string;
}) {
  const Icon = getProviderIcon(provider);
  return <Icon className={className} />;
}
