export interface ChartLegendItem {
  label: string;
  color: string;
}

interface ChartLegendProps {
  items: ChartLegendItem[];
}

export function ChartLegend({ items }: ChartLegendProps) {
  return (
    <div className="mt-4 inline-flex gap-[46px] rounded-full border-2 bg-card-border px-[19px] py-[9px]">
      {items.map((item, index) => (
        <div key={`legend-${index}`} className="flex items-center gap-1">
          <div
            className="h-3 w-3 rounded"
            style={{ backgroundColor: item.color }}
          />
          <span className="text-xs text-gray-300">{item.label}</span>
        </div>
      ))}
    </div>
  );
}
