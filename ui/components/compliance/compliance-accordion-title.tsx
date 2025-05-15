import { StatusFindingBadge } from "@/components/ui/table";

interface ComplianceAccordionTitleProps {
  label: string;
  pass: number;
  fail: number;
  manual?: number;
}

export const ComplianceAccordionTitle = ({
  label,
  pass,
  fail,
  manual = 0,
}: ComplianceAccordionTitleProps) => {
  return (
    <div className="flex flex-col items-start justify-between gap-1 md:flex-row md:items-center md:gap-0">
      <div className="w-1/2 overflow-hidden md:min-w-0">
        <span
          className="block w-full overflow-hidden truncate text-ellipsis pr-2 uppercase"
          title={label}
        >
          {label}
        </span>
      </div>
      <div className="flex items-center justify-center gap-2">
        <div className="hidden lg:block">
          {(pass > 0 || fail > 0 || manual > 0) && (
            <span className="mr-1 whitespace-nowrap text-xs font-medium text-gray-600">
              Requirements:
            </span>
          )}
        </div>

        <StatusFindingBadge status="PASS" value={pass} />
        <StatusFindingBadge status="FAIL" value={fail} />
        <StatusFindingBadge status="MANUAL" value={manual} />
      </div>
    </div>
  );
};
