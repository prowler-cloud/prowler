import { ProviderBadgeIcon } from "@/components/icons/providers-badge/provider-badge-icon";
import { InfoTooltip } from "@/components/shadcn/info-field/info-field";
import { FindingStatus, StatusFindingBadge } from "@/components/ui/table";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";
import { getProviderLabel } from "@/lib/providers/provider-display";
import { cn } from "@/lib/utils";
import { RequirementStatus } from "@/types/compliance";

interface ComplianceAccordionRequirementTitleProps {
  type: string;
  name: string;
  status: FindingStatus;
  invalidConfig?: boolean;
  /** Cross-provider mode only: per-provider statuses contributing to the
   *  rolled-up ``status``. When provided, a row of compact chips is rendered
   *  next to the rolled-up badge so the user can spot per-provider drift
   *  without expanding the requirement. Per-scan mode leaves this
   *  ``undefined`` and the header remains identical to before. */
  providers?: Record<string, RequirementStatus>;
}

const STATUS_DOT_CLASS_BY_STATUS: Record<RequirementStatus, string> = {
  PASS: "bg-bg-pass",
  FAIL: "bg-bg-fail",
  MANUAL: "bg-text-neutral-secondary",
  "No findings": "bg-text-neutral-secondary",
};

export const ComplianceAccordionRequirementTitle = ({
  type,
  name,
  status,
  invalidConfig = false,
  providers,
}: ComplianceAccordionRequirementTitleProps) => {
  const providerEntries = providers ? Object.entries(providers) : [];

  return (
    <div className="flex w-full flex-wrap items-center justify-between gap-2">
      <div className="flex min-w-0 flex-1 items-center gap-2">
        {type && (
          <span className="bg-primary/10 text-primary rounded-md px-2 py-0.5 text-xs font-medium">
            {type}
          </span>
        )}
        <span className="text-text-neutral-primary truncate">{name}</span>
        {invalidConfig && <InfoTooltip content={INVALID_CONFIG_NOTE} />}
      </div>
      {/* The accordion trigger this title lives in applies ``hover:underline``
          to all its text — fine for the plain requirement name, but it paints
          straight through the provider chips and status pill below. Opt this
          whole cluster out so hovering the row never underlines a badge. */}
      <div className="flex flex-wrap items-center gap-2 no-underline">
        {providerEntries.length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            {providerEntries.map(([providerKey, providerStatus]) => {
              const label = getProviderLabel(providerKey);
              return (
                <span
                  key={providerKey}
                  className="border-border-neutral-secondary inline-flex items-center gap-1 rounded border px-1.5 py-0.5"
                  title={`${label}: ${providerStatus}`}
                >
                  <ProviderBadgeIcon providerKey={providerKey} size={12} />
                  <span className="text-[10px] font-semibold">{label}</span>
                  <span
                    className={cn(
                      "size-1.5 rounded-full",
                      STATUS_DOT_CLASS_BY_STATUS[providerStatus] ??
                        "bg-text-neutral-secondary",
                    )}
                    aria-label={providerStatus}
                  />
                </span>
              );
            })}
          </div>
        )}
        {providerEntries.length > 0 ? (
          // Fixed width, not just the badge's own ``min-w`` — "Manual" is
          // visibly wider than "Pass"/"Fail", and this cluster is right-
          // justified, so a variable-width badge shifts the provider chips
          // left/right depending on which status happens to render. Locking
          // the slot width keeps the chips at the same x across every row.
          // Scoped to cross-provider mode only (``providerEntries.length``)
          // — every other framework has no chips to keep aligned, so it
          // keeps the badge at its natural width instead of losing space
          // to an empty fixed slot.
          <div className="flex w-[72px] shrink-0 justify-end">
            <StatusFindingBadge status={status} />
          </div>
        ) : (
          <StatusFindingBadge status={status} />
        )}
      </div>
    </div>
  );
};
