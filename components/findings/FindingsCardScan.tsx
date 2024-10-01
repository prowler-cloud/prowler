import { format, parseISO } from "date-fns";
import React from "react";

interface FindingsCardScanProps {
  title: string;
  dateTime: string;
}

export const FindingsCardScan: React.FC<FindingsCardScanProps> = ({
  title,
  dateTime = "",
}) => {
  const date = dateTime && parseISO(dateTime);
  const formattedDate = date && format(date, "MMM dd, yyyy");
  const formattedTime = date && format(date, "p 'UTC'");

  return (
    <>
      <p className="mt-3 text-sm font-bold">{title}</p>
      <p className="text-sm">
        {formattedDate} at {formattedTime}
      </p>
    </>
  );
};
