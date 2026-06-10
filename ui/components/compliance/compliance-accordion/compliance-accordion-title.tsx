import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/shadcn";

interface ComplianceAccordionTitleProps {
  label: string;
  pass: number;
  fail: number;
  manual?: number;
  isParentLevel?: boolean;
}

export const ComplianceAccordionTitle = ({
  label,
  pass,
  fail,
  manual = 0,
  isParentLevel = false,
}: ComplianceAccordionTitleProps) => {
  const total = pass + fail + manual;
  const passPercentage = (pass / total) * 100;
  const failPercentage = (fail / total) * 100;
  const manualPercentage = (manual / total) * 100;

  return (
    <div className="flex flex-col items-start justify-between gap-1 md:flex-row md:items-center md:gap-2">
      <div className="overflow-hidden md:min-w-0 md:flex-1">
        <span
          className="block max-w-[200px] truncate text-sm text-ellipsis sm:max-w-[300px] md:max-w-[400px] lg:max-w-[600px]"
          title={label}
        >
          {label.charAt(0).toUpperCase() + label.slice(1)}
        </span>
      </div>
      <div className="mr-4 flex items-center gap-2">
        <div className="hidden lg:block">
          {total > 0 && isParentLevel && (
            <span className="text-xs font-medium whitespace-nowrap text-gray-600">
              Requirements:
            </span>
          )}
        </div>

        <div className="flex h-1.5 w-[200px] overflow-hidden rounded-full bg-gray-100 shadow-inner">
          {total > 0 ? (
            <div className="flex w-full">
              {pass > 0 && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span
                      className="inline-block h-full bg-[#3CEC6D] transition-all duration-200 hover:brightness-110"
                      style={{
                        width: `${passPercentage}%`,
                        marginRight: pass > 0 ? "2px" : "0",
                      }}
                    />
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <div className="px-1 py-0.5">
                      <div className="text-xs font-medium">Pass</div>
                      <div className="text-text-neutral-tertiary text-xs">
                        {pass} ({passPercentage.toFixed(1)}%)
                      </div>
                    </div>
                  </TooltipContent>
                </Tooltip>
              )}
              {fail > 0 && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span
                      className="inline-block h-full bg-[#FB718F] transition-all duration-200 hover:brightness-110"
                      style={{
                        width: `${failPercentage}%`,
                        marginRight: manual > 0 ? "2px" : "0",
                      }}
                    />
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <div className="px-1 py-0.5">
                      <div className="text-xs font-medium">Fail</div>
                      <div className="text-text-neutral-tertiary text-xs">
                        {fail} ({failPercentage.toFixed(1)}%)
                      </div>
                    </div>
                  </TooltipContent>
                </Tooltip>
              )}
              {manual > 0 && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span
                      className="inline-block h-full bg-[#868994] transition-all duration-200 hover:brightness-110"
                      style={{ width: `${manualPercentage}%` }}
                    />
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <div className="px-1 py-0.5">
                      <div className="text-xs font-medium">Manual</div>
                      <div className="text-text-neutral-tertiary text-xs">
                        {manual} ({manualPercentage.toFixed(1)}%)
                      </div>
                    </div>
                  </TooltipContent>
                </Tooltip>
              )}
            </div>
          ) : (
            <div className="h-full w-full bg-gray-200" />
          )}
        </div>

        <Tooltip>
          <TooltipTrigger asChild>
            <span className="text-text-neutral-secondary min-w-[32px] text-center text-xs font-medium">
              {total > 0 ? total : "—"}
            </span>
          </TooltipTrigger>
          <TooltipContent side="top">
            <div className="px-1 py-0.5">
              <div className="text-xs font-medium">Total requirements</div>
              <div className="text-text-neutral-tertiary text-xs">{total}</div>
            </div>
          </TooltipContent>
        </Tooltip>
      </div>
    </div>
  );
};
