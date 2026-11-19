import type { AiResultCounts } from "@/app/(prowler)/ai-security/_types";
import { cn } from "@/lib/utils";

interface ResultBarProps extends AiResultCounts {
  /** What the bar measures, read out before the counts. */
  label: string;
  className?: string;
}

/** Pass, fail and manual as shares of one bar. */
export function ResultBar({
  label,
  pass,
  fail,
  manual,
  className,
}: ResultBarProps) {
  const total = pass + fail + manual;
  const share = (count: number) => `${total ? (count / total) * 100 : 0}%`;

  return (
    <div
      role="img"
      aria-label={`${label}: ${pass} pass, ${fail} fail, ${manual} manual`}
      className={cn(
        "bg-bg-neutral-secondary flex h-2 overflow-hidden rounded-full",
        className,
      )}
    >
      <span style={{ width: share(pass) }} className="bg-bg-pass" />
      <span style={{ width: share(fail) }} className="bg-bg-fail" />
      <span style={{ width: share(manual) }} className="bg-bg-data-muted" />
    </div>
  );
}

const LEGEND = [
  ["Pass", "bg-bg-pass"],
  ["Fail", "bg-bg-fail"],
  ["Manual", "bg-bg-data-muted"],
] as const;

export const ResultLegend = () => (
  <ul aria-hidden className="text-text-neutral-secondary flex gap-4 text-xs">
    {LEGEND.map(([name, color]) => (
      <li key={name} className="flex items-center gap-1.5">
        <span className={cn("size-2.5 rounded-sm", color)} />
        {name}
      </li>
    ))}
  </ul>
);
