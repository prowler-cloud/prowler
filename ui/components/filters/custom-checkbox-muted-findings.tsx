import { Checkbox } from "@nextui-org/react";
import React from "react";

export const CustomCheckboxMutedFindings = () => {
  return (
    <Checkbox
      classNames={{
        label: "text-small",
        wrapper: "checkbox-update xl:-mt-8",
      }}
      size="md"
      color="danger"
      aria-label="Include Muted Findings"
    >
      Include Muted Findings
    </Checkbox>
  );
};
