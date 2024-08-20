import { Checkbox } from "@nextui-org/react";
import React from "react";

interface CustomCheckboxMutedFindingsProps {
  mutedFindings?: boolean;
}

export const CustomCheckboxMutedFindings: React.FC<
  CustomCheckboxMutedFindingsProps
> = ({ mutedFindings }) => {
  return (
    <>
      {mutedFindings && (
        <Checkbox className="xl:-mt-8" size="md" color="danger">
          Include Muted Findings
        </Checkbox>
      )}
    </>
  );
};
