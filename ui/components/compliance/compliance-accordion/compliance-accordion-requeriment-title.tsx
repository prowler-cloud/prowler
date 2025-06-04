import { FindingStatus, StatusFindingBadge } from "@/components/ui/table";

interface ComplianceAccordionRequirementTitleProps {
  type: string;
  name: string;
  status: FindingStatus;
}

export const ComplianceAccordionRequirementTitle = ({
  name,
  status,
}: ComplianceAccordionRequirementTitleProps) => {
  return (
    <div className="flex w-full items-center justify-between gap-2">
      <div className="flex w-3/4 items-center gap-1">
        <span className="text-sm">{name}</span>
      </div>
      <StatusFindingBadge status={status} />
    </div>
  );
};
