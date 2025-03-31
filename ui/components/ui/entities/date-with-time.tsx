import { format, parseISO } from "date-fns";
import React from "react";

interface DateWithTimeProps {
  dateTime: string | null; // e.g., "2024-07-17T09:55:14.191475Z"
  showTime?: boolean;
  inline?: boolean;
}

export const DateWithTime: React.FC<DateWithTimeProps> = ({
  dateTime,
  showTime = true,
  inline = false,
}) => {
  if (!dateTime) return <span>--</span>;

  try {
    const date = parseISO(dateTime);

    // Validate if the date is valid
    if (isNaN(date.getTime())) {
      return <span>-</span>;
    }

    const formattedDate = format(date, "MMM dd, yyyy");
    const formattedTime = format(date, "p 'UTC'");

    return (
      <div className="mw-fit py-[2px]">
        <div
          className={`flex ${inline ? "flex-row items-center gap-2" : "flex-col"}`}
        >
          <span className="text-xs font-semibold">{formattedDate}</span>
          {showTime && (
            <span className="text-xs text-gray-500">{formattedTime}</span>
          )}
        </div>
      </div>
    );
  } catch (error) {
    return <span>-</span>;
  }
};
