"use client";

import {
  getProviderLogo,
  getProviderName,
} from "@/components/shadcn/entities/get-provider-logo";
import {
  getProviderDisplayName,
  isKnownProviderType,
  type ProviderType,
} from "@/types/providers";

export const ProviderTitleDocs = ({
  providerType,
}: {
  providerType: ProviderType;
}) => {
  const isKnown = isKnownProviderType(providerType);
  return (
    <div className="flex gap-4">
      {isKnown && getProviderLogo(providerType)}
      <span className="text-lg font-semibold">
        {isKnown
          ? getProviderName(providerType)
          : getProviderDisplayName(providerType)}
      </span>
    </div>
  );
};
