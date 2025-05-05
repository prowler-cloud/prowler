import { Tooltip } from "@nextui-org/react";

import { cn } from "@/lib/utils";

interface DeltaTooltipProps {
  delta: string;
  className?: string;
}

export const DeltaTooltip = ({ delta, className }: DeltaTooltipProps) => {
  return (
    <Tooltip
      content={
        <div className="flex gap-1 text-xs">
          <span>
            {delta === "new"
              ? "New finding."
              : "Status changed since the previous scan."}
          </span>
          <a
            href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-8-analyze-the-findings"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary"
          >
            Learn more
          </a>
        </div>
      }
    >
      <div
        className={cn(
          "h-2 w-2 cursor-pointer rounded-full",
          delta === "new"
            ? "bg-system-severity-high"
            : delta === "changed"
              ? "bg-system-severity-medium"
              : "bg-gray-500",
          className,
        )}
      />
    </Tooltip>
  );
};
