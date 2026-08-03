"use client";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import type { CheckProviderTypesMap } from "@/types/compliance";

interface ChecksWithProvidersProps {
  checks: string[];
  checkProviders: CheckProviderTypesMap;
}

/**
 * Provider-labeled check list for the cross-provider requirement view: each
 * check id followed by the icons of the provider types it belongs to. Checks
 * missing from the map render without icons.
 */
export const ChecksWithProviders = ({
  checks,
  checkProviders,
}: ChecksWithProvidersProps) => (
  <ul className="flex flex-wrap gap-x-4 gap-y-1">
    {checks.map((checkId) => (
      <li
        key={checkId}
        data-testid={`check-with-providers-${checkId}`}
        className="flex items-center gap-1.5"
      >
        <span className="text-gray-600 dark:text-gray-200">{checkId}</span>
        <span className="flex items-center gap-1">
          {(checkProviders[checkId] ?? []).map((type) => (
            <ProviderTypeIcon key={type} type={type} size={14} />
          ))}
        </span>
      </li>
    ))}
  </ul>
);
