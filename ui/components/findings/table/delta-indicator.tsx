import { Tooltip } from "@nextui-org/react";

import { CustomLink } from "@/components/ui/custom";
import { cn } from "@/lib/utils";

interface DeltaIndicatorProps {
  delta: string;
}

export const DeltaIndicator = ({ delta }: DeltaIndicatorProps) => {
  return (
    <Tooltip
      className="pointer-events-auto"
      content={
        <div className="flex gap-1 text-xs">
          <span>
            {delta === "new"
              ? "New finding."
              : "Status changed since the previous scan."}
          </span>
          <CustomLink
            ariaLabel="Learn more about findings"
            color="transparent"
            className="h-auto min-w-0 p-0 text-xs text-primary"
            path="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-8-analyze-the-findings"
            target="_blank"
          >
            Learn more
          </CustomLink>
        </div>
      }
    >
      <div
        className={cn(
          "h-2 w-2 min-w-2 cursor-pointer rounded-full",
          delta === "new"
            ? "bg-system-severity-high"
            : delta === "changed"
              ? "bg-system-severity-low"
              : "bg-gray-500",
        )}
      />
    </Tooltip>
  );
};
