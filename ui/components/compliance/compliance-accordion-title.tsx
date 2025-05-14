import { Chip } from "@nextui-org/react";

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
  // Determine if it is a requirement (level 4), control (level 3) or higher level
  // The names of requirements are like "op.exp.5.aws.cm.1"
  const isRequirementLevel = /\.\w+\.\d+$/.test(label); // Check if it ends with .word.number
  const isControlLevel = label.includes(" - ") && !isRequirementLevel;

  let prefix = "Requirements";
  if (isRequirementLevel) {
    prefix = "Findings";
  } else if (isControlLevel) {
    prefix = "Requirements";
  }

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
              {prefix}:
            </span>
          )}
        </div>

        <Chip
          size="sm"
          color="success"
          variant="flat"
          className="whitespace-nowrap"
        >
          Pass: {pass}
        </Chip>

        <Chip
          size="sm"
          color="danger"
          variant="flat"
          className="whitespace-nowrap"
        >
          Fail: {fail}
        </Chip>

        <Chip
          size="sm"
          color="default"
          variant="bordered"
          className="whitespace-nowrap"
        >
          Manual: {manual}
        </Chip>
      </div>
    </div>
  );
};
