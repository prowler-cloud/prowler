"use client";

import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import { buildCrossAccountDetailHref } from "../_lib/cross-account-frameworks";
import type { CrossAccountFrameworkEntry } from "../_types";

/**
 * Card for a regular per-provider framework in the Cross-Provider tab's
 * "across accounts" section. Deliberately lightweight — no roll-up numbers:
 * the section only enumerates which frameworks can be viewed across accounts
 * (computing every framework's N-account aggregation up front would be one
 * heavy roll-up call per card). The detail computes the real aggregation.
 */
export const CrossAccountFrameworkCard = ({
  complianceId,
  title,
  version,
  providerType,
  accountCount,
}: CrossAccountFrameworkEntry) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const formattedTitle = `${title.split("-").join(" ")}${version ? ` - ${version}` : ""}`;

  const navigateToDetail = () => {
    router.push(
      buildCrossAccountDetailHref(
        { complianceId, title, version, providerType },
        Object.fromEntries(searchParams.entries()),
      ),
    );
  };

  return (
    <Card
      variant="base"
      padding="md"
      className="relative cursor-pointer transition-shadow hover:shadow-md"
      onClick={navigateToDetail}
      role="button"
      aria-label={`${formattedTitle} across ${PROVIDER_DISPLAY_NAMES[providerType]} providers`}
      tabIndex={0}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          navigateToDetail();
        }
      }}
    >
      <CardContent className="p-0">
        <div className="flex w-full flex-col gap-3">
          <div className="flex items-center gap-3">
            {getComplianceIcon(title) && (
              <div className="flex h-10 w-10 min-w-10 shrink-0 items-center justify-center rounded-md border border-gray-300 bg-white">
                <Image
                  src={getComplianceIcon(title)}
                  alt={`${title} logo`}
                  width={32}
                  height={32}
                  className="h-8 w-8 object-contain"
                />
              </div>
            )}
            <div className="flex min-w-0 flex-1 flex-col">
              <h4 className="truncate text-sm leading-5 font-bold">
                {formattedTitle}
              </h4>
              <small className="text-text-neutral-secondary truncate text-xs">
                View across providers
              </small>
            </div>
          </div>

          <div className="flex items-center justify-between gap-3">
            <span className="inline-flex items-center gap-1.5 text-xs">
              <ProviderTypeIcon type={providerType} size={16} />
              {PROVIDER_DISPLAY_NAMES[providerType]}
            </span>
            <span className="text-text-neutral-secondary text-xs whitespace-nowrap">
              {accountCount} providers
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
