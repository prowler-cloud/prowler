export interface ChartLegendItem {
  label: string;
  color: string;
  dataKey?: string;
}

interface ChartLegendProps {
  items: ChartLegendItem[];
  selectedItem?: string | null;
  onItemClick?: (dataKey: string) => void;
}

export function ChartLegend({
  items,
  selectedItem,
  onItemClick,
}: ChartLegendProps) {
  const isInteractive = !!onItemClick;

  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary inline-flex items-center gap-2 rounded-full border">
      {items.map((item, index) => {
        const dataKey = item.dataKey ?? item.label.toLowerCase();
        const isSelected = selectedItem === dataKey;
        const isFaded = selectedItem !== null && !isSelected;

        return (
          <button
            key={`legend-${index}`}
            type="button"
            className={`flex items-center gap-2 px-4 py-3 transition-opacity duration-200 ${
              isInteractive ? "cursor-pointer hover:opacity-80" : "cursor-default"
            } ${isFaded ? "opacity-30" : "opacity-100"}`}
            onClick={() => onItemClick?.(dataKey)}
            disabled={!isInteractive}
          >
            <div
              className={`h-3 w-3 rounded ${isSelected ? "ring-2 ring-offset-1" : ""}`}
              style={{
                backgroundColor: item.color,
                // @ts-expect-error ring-color is a valid Tailwind CSS variable
                "--tw-ring-color": item.color,
              }}
            />
            <span className="text-text-neutral-secondary text-sm font-medium">
              {item.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}
