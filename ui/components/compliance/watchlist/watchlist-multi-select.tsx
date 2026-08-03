"use client";

import { useState, useTransition } from "react";

import { bulkUpdateComplianceWatchlist } from "@/actions/compliance-watchlist";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectGroup,
  MultiSelectItem,
  MultiSelectTrigger,
} from "@/components/shadcn/select/multiselect";
import { useToast } from "@/components/shadcn/toast/use-toast";
import {
  computeWatchlistDiff,
  exceedsWatchlistBulkLimit,
  isEmptyWatchlistDiff,
  MAX_WATCHLIST_BULK,
  watchlistKey,
} from "@/lib/compliance/watchlist";
import type {
  ComplianceCatalogEntry,
  ComplianceWatchlistTarget,
} from "@/types/compliance-watchlist";
import { WATCHLIST_SCOPE } from "@/types/compliance-watchlist";
import { getProviderDisplayName } from "@/types/providers";

interface WatchlistMultiSelectProps {
  /** Every framework the tenant may pin, across both compliance tabs. Their
   *  `inWatchlist` flags are the baseline the submitted diff is computed
   *  against. */
  entries: ComplianceCatalogEntry[];
  id?: string;
}

/** Heading of the group a universal framework belongs to. Universal frameworks
 *  span every compatible provider type, so they get their own band instead of
 *  being repeated under each one. */
const UNIVERSAL_GROUP_LABEL = "Universal";

interface WatchlistGroup {
  key: string;
  label: string;
  entries: ComplianceCatalogEntry[];
}

const frameworkLabel = (entry: ComplianceCatalogEntry): string =>
  `${entry.framework}${entry.version ? ` - ${entry.version}` : ""}`;

/**
 * Universal frameworks first, then one group per provider type in display-name
 * order. The heading rides above the first framework of each band, which is
 * what tells CIS Controls (universal) apart from CIS AWS at a glance — the two
 * are otherwise a single alphabetical list of near-identical names.
 */
const buildGroups = (entries: ComplianceCatalogEntry[]): WatchlistGroup[] => {
  const universal = entries.filter(
    (entry) => entry.scope === WATCHLIST_SCOPE.UNIVERSAL,
  );

  const byProviderType = new Map<string, ComplianceCatalogEntry[]>();
  for (const entry of entries) {
    if (entry.scope === WATCHLIST_SCOPE.UNIVERSAL) continue;
    byProviderType.set(entry.providerType, [
      ...(byProviderType.get(entry.providerType) ?? []),
      entry,
    ]);
  }

  const sortEntries = (group: ComplianceCatalogEntry[]) =>
    [...group].sort((a, b) =>
      frameworkLabel(a).localeCompare(frameworkLabel(b)),
    );

  const providerGroups: WatchlistGroup[] = Array.from(byProviderType.entries())
    .map(([providerType, group]) => ({
      key: providerType,
      label: getProviderDisplayName(providerType),
      entries: sortEntries(group),
    }))
    .sort((a, b) => a.label.localeCompare(b.label));

  return [
    ...(universal.length > 0
      ? [
          {
            key: WATCHLIST_SCOPE.UNIVERSAL,
            label: UNIVERSAL_GROUP_LABEL,
            entries: sortEntries(universal),
          },
        ]
      : []),
    ...providerGroups,
  ];
};

const pinnedKeys = (entries: ComplianceCatalogEntry[]): string[] =>
  entries
    .filter((entry) => entry.inWatchlist)
    .map((entry) => watchlistKey(entry));

const toTarget = (
  entry: ComplianceCatalogEntry,
): ComplianceWatchlistTarget => ({
  complianceId: entry.complianceId,
  providerType: entry.providerType,
});

/**
 * Watchlist editor that lives next to the compliance tabs, replacing the
 * full-width curated section each tab used to carry.
 *
 * Edits are buffered and submitted as one diff when the dropdown closes, so
 * ticking a dozen frameworks costs a single request — and only the entries this
 * user actually touched are written, leaving a concurrent edit by another
 * member intact. Per-card pins remain the quick path for a single framework.
 */
export const WatchlistMultiSelect = ({
  entries,
  id = "compliance-watchlist-selector",
}: WatchlistMultiSelectProps) => {
  const { toast } = useToast();
  const [isPending, startTransition] = useTransition();
  const [open, setOpen] = useState(false);
  const labelId = `${id}-label`;
  // Local state needed: selections are pending edits, applied only on close.
  const [selectedKeys, setSelectedKeys] = useState<string[]>(() =>
    pinnedKeys(entries),
  );

  const groups = buildGroups(entries);

  const submit = (nextKeys: string[]) => {
    const selected = new Set(nextKeys);
    const diff = computeWatchlistDiff(
      entries.filter((entry) => entry.inWatchlist).map(toTarget),
      entries
        .filter((entry) => selected.has(watchlistKey(entry)))
        .map(toTarget),
    );

    if (isEmptyWatchlistDiff(diff)) return;

    if (exceedsWatchlistBulkLimit(diff)) {
      toast({
        variant: "destructive",
        title: "Too many changes at once",
        description: `A single update may reference at most ${MAX_WATCHLIST_BULK} frameworks. Apply the changes in smaller batches.`,
      });
      // Discard the oversized batch rather than leaving the dropdown claiming
      // changes the server never received.
      setSelectedKeys(pinnedKeys(entries));
      return;
    }

    startTransition(async () => {
      const result = await bulkUpdateComplianceWatchlist(diff);

      if (result.error) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: result.error,
        });
        setSelectedKeys(pinnedKeys(entries));
        return;
      }

      toast({ title: "Watchlist updated", description: result.success });
    });
  };

  const handleOpenChange = (nextOpen: boolean) => {
    // Reopening re-reads the server state, so a pin toggled from a card — or by
    // another member — is reflected instead of being undone by a stale buffer.
    if (nextOpen) {
      setSelectedKeys(pinnedKeys(entries));
    } else {
      submit(selectedKeys);
    }
    setOpen(nextOpen);
  };

  const pinnedCount = selectedKeys.length;

  return (
    <div className="relative">
      <label htmlFor={id} className="sr-only" id={labelId}>
        Compliance watchlist. Select the frameworks your organization wants to
        keep an eye on.
      </label>
      <MultiSelect
        values={selectedKeys}
        onValuesChange={setSelectedKeys}
        open={open}
        onOpenChange={handleOpenChange}
      >
        <MultiSelectTrigger
          id={id}
          size="sm"
          disabled={isPending}
          aria-labelledby={labelId}
        >
          {/* Not `MultiSelectValue`: a badge per pinned framework would spill
              past the tab bar once a handful are pinned. */}
          <span className="truncate">
            {pinnedCount > 0
              ? `Watchlist · ${pinnedCount.toLocaleString()} pinned`
              : "Watchlist · none pinned"}
          </span>
        </MultiSelectTrigger>
        <MultiSelectContent
          width="wide"
          search={{
            placeholder: "Search frameworks...",
            emptyMessage: "No frameworks match your search.",
          }}
        >
          {groups.map((group) => (
            <MultiSelectGroup key={group.key} heading={group.label}>
              {group.entries.map((entry) => {
                const label = frameworkLabel(entry);

                return (
                  <MultiSelectItem
                    key={watchlistKey(entry)}
                    value={watchlistKey(entry)}
                    badgeLabel={label}
                    keywords={[entry.framework, entry.name, entry.complianceId]}
                  >
                    <span className="truncate">{label}</span>
                  </MultiSelectItem>
                );
              })}
            </MultiSelectGroup>
          ))}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
};
