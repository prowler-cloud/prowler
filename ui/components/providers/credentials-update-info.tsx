"use client";

import {
  getSelectorComponentKey,
  PROVIDER_SELECTOR_COMPONENTS,
} from "@/lib/provider-helpers";
import { ProviderType } from "@/types/providers";

interface UpdateCredentialsInfoProps {
  providerType: ProviderType;
  initialVia?: string;
}

export const CredentialsUpdateInfo = ({
  providerType,
  initialVia,
}: UpdateCredentialsInfoProps) => {
  const componentKey = getSelectorComponentKey(providerType);

  if (!componentKey) return null;

  const SelectorComponent = PROVIDER_SELECTOR_COMPONENTS[componentKey];

  return (
    <div className="flex flex-col gap-4">
      <SelectorComponent initialVia={initialVia} />
    </div>
  );
};
