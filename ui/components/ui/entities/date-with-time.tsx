import { format, parseISO } from "date-fns";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

interface DateWithTimeProps {
  dateTime: string | null; // e.g., "2024-07-17T09:55:14.191475Z"
  showTime?: boolean;
  inline?: boolean;
}

export const DateWithTime = ({
  dateTime,
  showTime = true,
  inline = false,
}: DateWithTimeProps) => {
  if (!dateTime) return <span>--</span>;

  try {
    const date = parseISO(dateTime);

    // Validate if the date is valid
    if (isNaN(date.getTime())) {
      return <span>-</span>;
    }

    const formattedDate = format(date, "MMM dd, yyyy");
    const formattedTime = format(date, "h:mma");
    const timezone =
      Intl.DateTimeFormat()
        .resolvedOptions()
        .timeZone.split("/")
        .pop()
        ?.substring(0, 3)
        .toUpperCase() || "";

    const fullText = showTime
      ? `${formattedDate} ${formattedTime} ${timezone}`
      : formattedDate;

    const content = (
      <div
        className={cn(
          "gap-1",
          inline
            ? "inline-flex flex-row items-center overflow-hidden"
            : "flex flex-col",
        )}
      >
        <span
          className={cn(
            "text-text-neutral-primary text-sm whitespace-nowrap",
            inline && "truncate",
          )}
        >
          {formattedDate}
        </span>
        {showTime && (
          <span
            className={cn(
              "text-text-neutral-tertiary text-xs font-medium whitespace-nowrap",
              inline && "truncate",
            )}
          >
            {formattedTime} {timezone}
          </span>
        )}
      </div>
    );

    if (inline) {
      return (
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="min-w-0 overflow-hidden">{content}</div>
          </TooltipTrigger>
          <TooltipContent>{fullText}</TooltipContent>
        </Tooltip>
      );
    }

    return content;
  } catch {
    return <span>-</span>;
  }
};
