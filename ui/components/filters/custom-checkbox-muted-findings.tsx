import { Checkbox } from "@nextui-org/react";
import React from "react";

export const CustomCheckboxMutedFindings = () => {
  return (
    <Checkbox
      className="xl:-mt-8"
      size="md"
      color="danger"
      aria-label="Include Muted Findings"
    >
      Include Muted Findings
    </Checkbox>
  );
};
