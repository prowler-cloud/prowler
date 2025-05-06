import { Tooltip } from "@nextui-org/react";

import { CustomButton } from "@/components/ui/custom/custom-button";
import { cn } from "@/lib/utils";

interface DeltaIndicatorProps {
  delta: string;
}

export const DeltaIndicator = ({ delta }: DeltaIndicatorProps) => {
  return (
    <Tooltip
      content={
        <div className="flex gap-1 text-xs">
          <span>
            {delta === "new"
              ? "New finding."
              : "Status changed since the previous scan."}
          </span>
          <CustomButton
            ariaLabel="Learn more about findings"
            color="transparent"
            size="sm"
            className="h-auto min-w-0 p-0 text-primary"
            asLink="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-8-analyze-the-findings"
            target="_blank"
          >
            Learn more
          </CustomButton>
        </div>
      }
    >
      <div
        className={cn(
          "h-2 w-2 min-w-2 cursor-pointer rounded-full",
          delta === "new"
            ? "bg-system-severity-high"
            : delta === "changed"
              ? "bg-system-severity-medium"
              : "bg-gray-500",
        )}
      />
    </Tooltip>
  );
};
