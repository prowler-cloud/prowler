"use client";

import { useState } from "react";

import { DataTableSearch } from "@/components/ui/table/data-table-search";

import { CrossProviderCard } from "./cross-provider-card";

export interface CrossProviderFrameworkSummary {
  id: string;
  title: string;
  version: string;
  description?: string;
  requirementsPassed: number;
  totalRequirements: number;
  /** Providers that actually contributed at least one scan to the
   *  aggregated view — rendered as "active" chips on the card. */
  contributingProviders: string[];
  /** Catalogue of providers the universal framework declares checks for —
   *  rendered as "compatible" chips on the card; the ones not in
   *  ``contributingProviders`` are shown dimmed to signal "no scan yet". */
  compatibleProviders: string[];
}

interface CrossProviderGridProps {
  frameworks: CrossProviderFrameworkSummary[];
}

/**
 * Grid of universal compliance frameworks shown under the "Cross-Provider"
 * tab. Mirrors the per-scan ``ComplianceOverviewGrid`` layout (search input
 * + responsive grid of cards) but each card aggregates the latest scan per
 * compatible provider instead of showing a single scan.
 */
export const CrossProviderGrid = ({ frameworks }: CrossProviderGridProps) => {
  const [searchTerm, setSearchTerm] = useState("");

  const filteredFrameworks = frameworks.filter((framework) =>
    framework.title.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <DataTableSearch
          controlledValue={searchTerm}
          onSearchChange={setSearchTerm}
          placeholder="Search universal frameworks..."
        />
        <span className="text-text-neutral-secondary shrink-0 text-sm">
          {filteredFrameworks.length.toLocaleString()} Total Entries
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
        {filteredFrameworks.map((framework) => (
          <CrossProviderCard
            key={framework.id}
            complianceId={framework.id}
            title={framework.title}
            version={framework.version}
            description={framework.description}
            requirementsPassed={framework.requirementsPassed}
            totalRequirements={framework.totalRequirements}
            contributingProviders={framework.contributingProviders}
            compatibleProviders={framework.compatibleProviders}
          />
        ))}
      </div>
    </>
  );
};
