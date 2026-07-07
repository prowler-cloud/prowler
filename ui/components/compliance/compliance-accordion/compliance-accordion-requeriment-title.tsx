import { InfoTooltip } from "@/components/shadcn/info-field/info-field";
import { FindingStatus, StatusFindingBadge } from "@/components/shadcn/table";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";

interface ComplianceAccordionRequirementTitleProps {
  type: string;
  name: string;
  status: FindingStatus;
  invalidConfig?: boolean;
}

export const ComplianceAccordionRequirementTitle = ({
  type,
  name,
  status,
  invalidConfig = false,
}: ComplianceAccordionRequirementTitleProps) => {
  return (
    <div className="flex w-full items-center justify-between gap-2">
      <div className="flex w-5/6 items-center gap-2">
        {type && (
          <span className="bg-button-primary/10 text-button-primary rounded-md px-2 py-0.5 text-xs font-medium">
            {type}
          </span>
        )}
        <span>{name}</span>
        {invalidConfig && <InfoTooltip content={INVALID_CONFIG_NOTE} />}
      </div>
      <StatusFindingBadge status={status} />
    </div>
  );
};
