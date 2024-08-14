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
      <p className="text-sm font-bold mt-3">{title}</p>
      <p className="text-sm">
        {formattedDate} at {formattedTime}
      </p>
    </>
  );
};
