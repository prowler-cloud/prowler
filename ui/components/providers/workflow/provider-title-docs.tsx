"use client";

import { getProviderName } from "@/components/ui/entities/get-provider-logo";
import { getProviderLogo } from "@/components/ui/entities/get-provider-logo";
import { ProviderType } from "@/types";

export const ProviderTitleDocs = ({
  providerType,
}: {
  providerType: ProviderType;
}) => {
  return (
    <div className="flex gap-4">
      {providerType && getProviderLogo(providerType as ProviderType)}
      <span className="text-lg font-semibold">
        {providerType
          ? getProviderName(providerType as ProviderType)
          : "Unknown Provider"}
      </span>
    </div>
  );
};
