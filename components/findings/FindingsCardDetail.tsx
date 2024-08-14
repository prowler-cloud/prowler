import { Button, Link } from "@nextui-org/react";
import React from "react";

interface FindingsCardDetailProps {
  title: string;
  url?: string;
  description: string;
  type?: DetailType;
}

type DetailType = "default" | "risk" | "recommendation" | "reference";

const getDetailColorClass = (type: DetailType): string => {
  switch (type) {
    case "risk":
      return "border-red-200";
    case "recommendation":
      return "border-green-200";
    case "reference":
      return "border-gray-200";
    case "default":
    default:
      return "border-yellow-200";
  }
};

export const FindingsCardDetail: React.FC<FindingsCardDetailProps> = ({
  title,
  url,
  description,
  type = "default",
}) => {
  return (
    <>
      {description && (
        <div
          className={`text-sm mt-3 rounded-md border-2 ${getDetailColorClass(type)} p-2`}
        >
          <p className="font-bold flex justify-between items-center mb-2">
            <span>{title}</span>
            {url && (
              <Button
                href={url}
                as={Link}
                color="primary"
                variant="flat"
                isExternal
                size="sm"
              >
                View Source
              </Button>
            )}
          </p>
          <p>{description}</p>
        </div>
      )}
    </>
  );
};
