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
      className="mt-4 inline-flex gap-[46px] rounded-full border-2 px-[19px] py-[9px]"
      style={{ borderColor: "var(--chart-border)" }}
    >
      {items.map((item, index) => (
        <div key={`legend-${index}`} className="flex items-center gap-1">
          <div
            className="h-3 w-3 rounded"
            style={{ backgroundColor: item.color }}
          />
          <span
            className="text-xs"
            style={{ color: "var(--chart-text-secondary)" }}
          >
            {item.label}
          </span>
        </div>
      ))}
    </div>
  );
}
