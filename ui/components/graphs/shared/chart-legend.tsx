import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

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
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary inline-flex max-w-full items-center overflow-hidden rounded-full border sm:gap-2">
      {items.map((item, index) => {
        const dataKey = item.dataKey ?? item.label.toLowerCase();
        const isSelected = selectedItem === dataKey;
        const isFaded = selectedItem !== null && !isSelected;

        return (
          <Tooltip key={`legend-${index}`}>
            <TooltipTrigger asChild>
              <button
                type="button"
                className={`flex min-w-0 items-center gap-1 px-2 py-3 transition-opacity duration-200 sm:gap-2 sm:px-4 ${
                  isInteractive
                    ? "cursor-pointer hover:opacity-80"
                    : "cursor-default"
                } ${isFaded ? "opacity-30" : "opacity-100"}`}
                onClick={() => onItemClick?.(dataKey)}
                disabled={!isInteractive}
              >
                <div
                  className={`h-3 w-3 shrink-0 rounded ${isSelected ? "ring-2 ring-offset-1" : ""}`}
                  style={{
                    backgroundColor: item.color,
                    // @ts-expect-error ring-color is a valid Tailwind CSS variable
                    "--tw-ring-color": item.color,
                  }}
                />
                <span className="text-text-neutral-secondary max-w-[120px] truncate text-sm font-medium sm:max-w-[200px]">
                  {item.label}
                </span>
              </button>
            </TooltipTrigger>
            <TooltipContent>
              <p>{item.label}</p>
            </TooltipContent>
          </Tooltip>
        );
      })}
    </div>
  );
}
