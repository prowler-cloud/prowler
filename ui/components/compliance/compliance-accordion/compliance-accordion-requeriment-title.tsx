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
      <div className="flex w-5/6 items-center gap-1">
        <span>{name}</span>
      </div>
      <StatusFindingBadge status={status} />
    </div>
  );
};
