import { format, parseISO } from "date-fns";
import React from "react";

interface DateWithTimeProps {
  dateTime: string; // e.g., "2024-07-17T09:55:14.191475Z"
  showTime?: boolean;
}

export const DateWithTime: React.FC<DateWithTimeProps> = ({
  dateTime,
  showTime = true,
}) => {
  const date = parseISO(dateTime);
  const formattedDate = format(date, "MMM dd, yyyy");
  const formattedTime = format(date, "p 'UTC'");

  return (
    <div className="max-w-fit">
      <div className="flex flex-col items-start">
        <span className="text-md font-semibold">{formattedDate}</span>
        {showTime && (
          <span className="text-sm text-gray-500">{formattedTime}</span>
        )}
      </div>
    </div>
  );
};
