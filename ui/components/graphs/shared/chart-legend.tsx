export interface ChartLegendItem {
  label: string;
  color: string;
}

interface ChartLegendProps {
  items: ChartLegendItem[];
}

export function ChartLegend({ items }: ChartLegendProps) {
  return (
    <div
      className="mt-4 inline-flex items-center gap-2 rounded-full border bg-neutral-900 p-1"
      style={{ borderColor: "var(--border-time-range)" }}
    >
      {items.map((item, index) => (
        <div
          key={`legend-${index}`}
          className="flex items-center gap-2 border-r border-zinc-800 px-4 py-3 last:border-r-0"
        >
          <div
            className="h-3 w-3 rounded"
            style={{ backgroundColor: item.color }}
          />
          <span
            className="text-sm font-medium"
            style={{ color: "var(--chart-text-secondary)" }}
          >
            {item.label}
          </span>
        </div>
      ))}
    </div>
  );
}
