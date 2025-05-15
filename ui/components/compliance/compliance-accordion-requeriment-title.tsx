import { FindingStatus, StatusFindingBadge } from "@/components/ui/table";
import { translateType } from "@/lib/ens-compliance";

interface ComplianceAccordionRequirementTitleProps {
  type: string;
  name: string;
  status: FindingStatus;
}

export const ComplianceAccordionRequirementTitle = ({
  type,
  name,
  status,
}: ComplianceAccordionRequirementTitleProps) => {
  return (
    <div className="flex w-full items-center justify-between gap-2">
      <div className="flex w-3/4 items-center gap-1">
        <span className="whitespace-nowrap text-sm font-bold capitalize">
          {translateType(type)}:
        </span>
        <span className="whitespace-nowrap text-sm uppercase">{name}</span>
      </div>
      <StatusFindingBadge status={status} />
    </div>
  );
};
