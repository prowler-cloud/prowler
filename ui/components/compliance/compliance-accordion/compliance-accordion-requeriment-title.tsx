import { FindingStatus, StatusFindingBadge } from "@/components/ui/table";

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
      <div className="flex w-5/6 items-center gap-2">
        {type && (
          <span className="bg-primary/10 text-primary rounded-md px-2 py-0.5 text-xs font-medium">
            {type}
          </span>
        )}
        <span>{name}</span>
      </div>
      <StatusFindingBadge status={status} />
    </div>
  );
};
