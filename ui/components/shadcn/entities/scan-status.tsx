import { formatDuration, intervalToDuration, parseISO } from "date-fns";
import React from "react";

interface ScanStatusProps {
  status: string;
  createdAt: string; // ISO string
}

export const ScanStatus: React.FC<ScanStatusProps> = ({
  status,
  createdAt,
}) => {
  const duration = intervalToDuration({
    start: parseISO(createdAt),
    end: new Date(),
  });

  const formattedDuration = formatDuration(duration, { delimiter: ", " });

  return (
    <div className="max-w-fit">
      <div className="flex flex-col">
        <span className="text-md font-semibold">{status}</span>
        <span className="text-sm text-gray-500">{formattedDuration}</span>
      </div>
    </div>
  );
};
