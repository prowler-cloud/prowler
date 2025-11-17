export interface ChartLegendItem {
  label: string;
  color: string;
}

interface ChartLegendProps {
  items: ChartLegendItem[];
}

export function ChartLegend({ items }: ChartLegendProps) {
  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary inline-flex items-center gap-2 rounded-full border">
      {items.map((item, index) => (
        <div
          key={`legend-${index}`}
          className="flex items-center gap-2 px-4 py-3"
        >
          <div
            className="h-3 w-3 rounded"
            style={{ backgroundColor: item.color }}
          />
          <span className="text-text-neutral-secondary text-sm font-medium">
            {item.label}
          </span>
        </div>
      ))}
    </div>
  );
}
