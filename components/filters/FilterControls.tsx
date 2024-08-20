import React from "react";

import { CustomAccountSelection } from "./CustomAccountSelection";
import { CustomCheckboxMutedFindings } from "./CustomCheckboxMutedFindings";
import { CustomDatePicker } from "./CustomDatePicker";
import { CustomSelectProvider } from "./CustomSelectProvider";

interface FilterControlsProps {
  mutedFindings?: boolean;
}

export const FilterControls: React.FC<FilterControlsProps> = ({
  mutedFindings = true,
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4 gap-y-4">
      <CustomSelectProvider />
      <CustomDatePicker />
      <CustomAccountSelection />
      <CustomCheckboxMutedFindings mutedFindings={mutedFindings} />
    </div>
  );
};
