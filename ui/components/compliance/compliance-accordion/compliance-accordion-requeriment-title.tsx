import { InfoTooltip } from "@/components/shadcn/info-field/info-field";
import { FindingStatus, StatusFindingBadge } from "@/components/ui/table";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";
import {
  getProviderBadge,
  getProviderLabel,
} from "@/lib/providers/provider-display";
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
        <span className="truncate">{name}</span>
        {invalidConfig && <InfoTooltip content={INVALID_CONFIG_NOTE} />}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {providerEntries.length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            {providerEntries.map(([providerKey, providerStatus]) => {
              const Badge = getProviderBadge(providerKey);
              const label = getProviderLabel(providerKey);
              return (
                <span
                  key={providerKey}
                  className="border-border-neutral-secondary inline-flex items-center gap-1 rounded border px-1.5 py-0.5"
                  title={`${label}: ${providerStatus}`}
                >
                  {Badge ? <Badge size={12} /> : null}
                  <span className="text-[10px] font-semibold uppercase">
                    {label}
                  </span>
                  <span
                    className={`size-1.5 rounded-full ${
                      STATUS_DOT_CLASS_BY_STATUS[providerStatus] ??
                      "bg-text-neutral-secondary"
                    }`}
                    aria-label={providerStatus}
                  />
                </span>
              );
            })}
          </div>
        )}
        <StatusFindingBadge status={status} />
      </div>
    </div>
  );
};
