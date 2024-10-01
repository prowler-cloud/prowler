import React from "react";

interface FindingsCardTypeProps {
  type: string[];
}

export const FindingsCardType: React.FC<FindingsCardTypeProps> = ({
  type = [],
}) => {
  const typeContent = () => {
    if (type.length > 0) {
      return type.join(", ");
    }
    return type[0];
  };

  return (
    <>
      <p className="mt-3 text-sm font-bold">
        {type.length > 1 ? "Types:" : "Type:"}
      </p>
      <p className="text-sm">{typeContent()}</p>
    </>
  );
};
