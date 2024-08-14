import { CustomAccountSelection } from "./CustomAccountSelection";
import { CustomCheckboxMutedFindings } from "./CustomCheckboxMutedFindings";
import { CustomDatePicker } from "./CustomDatePicker";
import { CustomSelectProvider } from "./CustomSelectProvider";

export const FilterControls = () => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-x-4 gap-y-4">
      <CustomSelectProvider />
      <CustomDatePicker />
      <CustomAccountSelection />
      <CustomCheckboxMutedFindings />
    </div>
  );
};
