"use client";

import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

import { accountDisplayLabel } from "../_lib/cross-account-adapter";
import type { AccountStatusMap, CrossAccountAccountRef } from "../_types";

import {
  REQUIREMENT_ENTITY_LABEL,
  RequirementStatusSummary,
} from "./requirement-status-summary";

interface RequirementAccountChipsProps {
  accounts: AccountStatusMap;
  /** Ordered account metadata (server-sorted by alias) so chips are stable
   *  across requirements. */
  accountMeta: CrossAccountAccountRef[];
}

/** Text labels are wide (aliases, 12-digit uids): beyond two accounts the
 *  inline chips would out-crowd the requirement title, so the row switches
 *  to the aggregated per-status summary. */
const MAX_INLINE_ACCOUNT_CHIPS = 2;

/** Per-account status chips shown next to a cross-account requirement:
 *  each contributing account's short label paired with its own
 *  PASS/FAIL/MANUAL — the account-axis sibling of RequirementProviderChips.
 *  With many accounts, collapses to per-status counts + hover breakdown. */
export const RequirementAccountChips = ({
  accounts,
  accountMeta,
}: RequirementAccountChipsProps) => {
  const entries = accountMeta.filter((account) => accounts[account.id]);

  if (entries.length > MAX_INLINE_ACCOUNT_CHIPS) {
    return (
      <RequirementStatusSummary
        entityLabel={REQUIREMENT_ENTITY_LABEL.ACCOUNTS}
        entries={entries.map((account) => ({
          key: account.id,
          label: accountDisplayLabel(account),
          status: accounts[account.id]!,
        }))}
      />
    );
  }

  return (
    // shrink-0: the chips keep their one-line intrinsic width and the row
    // TITLE truncates instead — compressed chips used to stack into two
    // lines or get clipped at the trigger's edge on long titles.
    <div className="flex shrink-0 items-center justify-end gap-2">
      {entries.map((account) => (
        <Tooltip key={account.id}>
          <TooltipTrigger asChild>
            <span
              data-testid={`requirement-chip-${account.id}`}
              className="inline-flex items-center gap-1"
            >
              <span className="text-text-neutral-secondary max-w-24 truncate text-xs">
                {account.alias || account.uid}
              </span>
              <StatusFindingBadge
                status={accounts[account.id] as FindingStatus}
                size="sm"
              />
            </span>
          </TooltipTrigger>
          <TooltipContent>{accountDisplayLabel(account)}</TooltipContent>
        </Tooltip>
      ))}
    </div>
  );
};
