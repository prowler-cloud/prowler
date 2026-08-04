"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import { buildCrossAccountDetailHref } from "../_lib/cross-account-frameworks";
import type { CrossAccountFrameworkEntry } from "../_types";

import { AggregatedFrameworkCard } from "./aggregated-framework-card";

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
    <AggregatedFrameworkCard
      frameworkTitle={title}
      formattedTitle={formattedTitle}
      ariaLabel={`${formattedTitle} across ${PROVIDER_DISPLAY_NAMES[providerType]} providers`}
      onActivate={navigateToDetail}
      subtitle={
        <small className="text-text-neutral-secondary truncate text-xs">
          View across providers
        </small>
      }
    >
      <div className="flex items-center justify-between gap-3">
        <span className="inline-flex items-center gap-1.5 text-xs">
          <ProviderTypeIcon type={providerType} size={16} />
          {PROVIDER_DISPLAY_NAMES[providerType]}
        </span>
        <span className="text-text-neutral-secondary text-xs whitespace-nowrap">
          {accountCount} providers
        </span>
      </div>
    </AggregatedFrameworkCard>
  );
};
