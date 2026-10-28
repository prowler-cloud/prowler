import {
  Combobox,
  type ComboboxGroup,
} from "@/components/shadcn/combobox/combobox";

interface ModelSelectProps {
  value: string;
  onValueChange: (value: string) => void;
  groups: ComboboxGroup[];
  isSaving: boolean;
}

// Keeps a minimum width so the composer chips wrap instead of squeezing it.
export function ModelSelect({
  value,
  onValueChange,
  groups,
  isSaving,
}: ModelSelectProps) {
  return (
    <div className="min-w-36 flex-1 sm:max-w-48">
      <Combobox
        aria-label="Model"
        value={value}
        onValueChange={onValueChange}
        groups={groups}
        disabled={groups.length === 0 || isSaving}
        placeholder="Select model"
        searchPlaceholder="Search models..."
        emptyMessage="No models found."
        size="sm"
      />
    </div>
  );
}
