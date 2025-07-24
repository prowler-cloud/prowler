"use client";

import { CustomLink } from "@/components/ui/custom/custom-link";
import { getProviderName } from "@/components/ui/entities/get-provider-logo";
import { getProviderLogo } from "@/components/ui/entities/get-provider-logo";
import { getProviderHelpText } from "@/lib";
import { ProviderType } from "@/types";

export const ProviderTitleDocs = ({
  providerType,
}: {
  providerType: ProviderType;
}) => {
  return (
    <div className="flex flex-col gap-y-2">
      <div className="flex space-x-4">
        {providerType && getProviderLogo(providerType as ProviderType)}
        <span className="text-lg font-semibold">
          {providerType
            ? getProviderName(providerType as ProviderType)
            : "Unknown Provider"}
        </span>
      </div>
      <div className="flex items-end gap-x-2">
        <p className="whitespace-nowrap text-sm text-default-500">
          {getProviderHelpText(providerType as string).text}
        </p>
        <CustomLink
          href={getProviderHelpText(providerType as string).link}
          size="sm"
        >
          Read the docs
        </CustomLink>
      </div>
    </div>
  );
};
