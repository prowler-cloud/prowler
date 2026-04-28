import { Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { DOCS_URLS } from "@/lib/external-urls";
import { cn } from "@/lib/utils";

interface DeltaIndicatorProps {
  delta: string;
}

export const DeltaIndicator = ({ delta }: DeltaIndicatorProps) => {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div
          className={cn(
            "h-2 w-2 min-w-2 cursor-pointer rounded-full",
            delta === "new"
              ? "bg-system-severity-high"
              : delta === "changed"
                ? "bg-system-severity-low"
                : "bg-text-neutral-tertiary",
          )}
        />
      </TooltipTrigger>
      <TooltipContent>
        <div className="flex gap-1 text-xs">
          <span>
            {delta === "new"
              ? "New finding."
              : "Status changed since the previous scan."}
          </span>
          <Button
            aria-label="Learn more about findings"
            variant="link"
            size="default"
            className="text-button-primary h-auto min-w-0 p-0 text-xs"
            asChild
          >
            <a
              href={DOCS_URLS.FINDINGS_ANALYSIS}
              target="_blank"
              rel="noopener noreferrer"
            >
              Learn more
            </a>
          </Button>
        </div>
      </TooltipContent>
    </Tooltip>
  );
};
