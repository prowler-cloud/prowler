import { Tooltip } from "@nextui-org/react";

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
  const total = pass + fail + manual;
  const passPercentage = (pass / total) * 100;
  const failPercentage = (fail / total) * 100;
  const manualPercentage = (manual / total) * 100;

  return (
    <div className="flex flex-col items-start justify-between gap-1 md:flex-row md:items-center md:gap-0">
      <div className="w-1/2 overflow-hidden md:min-w-0">
        <span
          className="block w-full overflow-hidden truncate text-ellipsis pr-2 text-sm"
          title={label}
        >
          {label.charAt(0).toUpperCase() + label.slice(1)}
        </span>
      </div>
      <div className="flex w-full items-center justify-center gap-2 md:w-1/2">
        <div className="hidden lg:block">
          {total > 0 && (
            <span className="mr-1 whitespace-nowrap text-xs font-medium text-gray-600">
              Requirements:
            </span>
          )}
        </div>

        <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-gray-100 shadow-inner">
          {total > 0 ? (
            <div className="flex w-full">
              {pass > 0 && (
                <Tooltip
                  content={
                    <div className="px-1 py-0.5">
                      <div className="text-xs font-medium">Pass</div>
                      <div className="text-tiny text-default-400">
                        {pass} ({passPercentage.toFixed(1)}%)
                      </div>
                    </div>
                  }
                  size="sm"
                  placement="top"
                  delay={0}
                  closeDelay={0}
                >
                  <div
                    className="h-full bg-[#3CEC6D] transition-all duration-200 hover:brightness-110"
                    style={{
                      width: `${passPercentage}%`,
                      marginRight: pass > 0 ? "2px" : "0",
                    }}
                  />
                </Tooltip>
              )}
              {fail > 0 && (
                <Tooltip
                  content={
                    <div className="px-1 py-0.5">
                      <div className="text-xs font-medium">Fail</div>
                      <div className="text-tiny text-default-400">
                        {fail} ({failPercentage.toFixed(1)}%)
                      </div>
                    </div>
                  }
                  size="sm"
                  placement="top"
                  delay={0}
                  closeDelay={0}
                >
                  <div
                    className="h-full bg-[#FB718F] transition-all duration-200 hover:brightness-110"
                    style={{
                      width: `${failPercentage}%`,
                      marginRight: manual > 0 ? "2px" : "0",
                    }}
                  />
                </Tooltip>
              )}
              {manual > 0 && (
                <Tooltip
                  content={
                    <div className="px-1 py-0.5">
                      <div className="text-xs font-medium">Manual</div>
                      <div className="text-tiny text-default-400">
                        {manual} ({manualPercentage.toFixed(1)}%)
                      </div>
                    </div>
                  }
                  size="sm"
                  placement="top"
                  delay={0}
                  closeDelay={0}
                >
                  <div
                    className="h-full bg-[#868994] transition-all duration-200 hover:brightness-110"
                    style={{ width: `${manualPercentage}%` }}
                  />
                </Tooltip>
              )}
            </div>
          ) : (
            <div className="h-full w-full bg-gray-200" />
          )}
        </div>

        <Tooltip
          content={
            <div className="px-1 py-0.5">
              <div className="text-xs font-medium">Total requirements</div>
              <div className="text-tiny text-default-400">{total}</div>
            </div>
          }
          size="sm"
          placement="top"
        >
          <div className="min-w-[32px] text-center text-xs font-medium text-default-600">
            {total > 0 ? total : "—"}
          </div>
        </Tooltip>
      </div>
    </div>
  );
};
