import { Link } from "@nextui-org/react";
import React from "react";

interface FindingsCardContentProps {
  title: string;
  url?: string;
  description: string;
}

export const FindingsCardContent: React.FC<FindingsCardContentProps> = ({
  title,
  url,
  description,
}) => {
  return (
    <>
      <p className="mt-3 text-sm font-bold">{title}</p>
      {url ? (
        <Link className="text-sm" href={url}>
          {description}
        </Link>
      ) : (
        <p className="text-sm">{description}</p>
      )}
    </>
  );
};
