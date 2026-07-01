interface ScoreDonutProps {
  /** Integer 0-100. */
  scorePercent: number;
  /** Pass count. */
  pass: number;
  /** Fail count. */
  fail: number;
  /** Manual count. */
  manual: number;
  /** Total requirements. */
  total: number;
  /** Pixel size of the SVG square. Defaults to 132. */
  size?: number;
  /** Stroke thickness. Defaults to 12. */
  stroke?: number;
}

/**
 * Compact circular score with an explicit pass/fail/manual stack bar
 * underneath. Pure SVG — no extra deps, scales cleanly in dark mode.
 *
 * The donut traces three arcs in succession (PASS → FAIL → MANUAL) so
 * the user reads the breakdown directly off the ring instead of
 * comparing it to a separate legend. The ring colors mirror the rest of
 * the compliance UI (``bg-pass`` / ``bg-fail`` / ``bg-warning``).
 */
export const ScoreDonut = ({
  scorePercent,
  pass,
  fail,
  manual,
  total,
  size = 132,
  stroke = 12,
}: ScoreDonutProps) => {
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const safeTotal = total > 0 ? total : 1;

  const passLen = (pass / safeTotal) * circumference;
  const failLen = (fail / safeTotal) * circumference;
  const manualLen = (manual / safeTotal) * circumference;
  const passOffset = 0;
  const failOffset = passLen;
  const manualOffset = passLen + failLen;

  const cx = size / 2;
  const cy = size / 2;

  // Pick a contrasting color for the central percent so dark surfaces
  // never wash it out, while doubling as a quick "how bad is it?"
  // signal: the central number adopts the dominant ring color.
  const centerColorClass =
    scorePercent >= 70
      ? "fill-bg-pass"
      : scorePercent >= 40
        ? "fill-bg-warning"
        : "fill-bg-fail";

  return (
    <div className="flex flex-col items-center gap-3">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        role="img"
        aria-label={`Compliance score ${scorePercent}%, ${pass} pass, ${fail} fail, ${manual} manual, ${total} total requirements`}
      >
        {/* Track */}
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={stroke}
          className="text-default-200 dark:text-default-100/30"
        />
        {/* Arcs — rotated so the trace starts at 12 o'clock */}
        <g transform={`rotate(-90 ${cx} ${cy})`}>
          {pass > 0 && (
            <circle
              cx={cx}
              cy={cy}
              r={radius}
              fill="none"
              stroke="currentColor"
              strokeWidth={stroke}
              strokeLinecap="butt"
              strokeDasharray={`${passLen} ${circumference - passLen}`}
              strokeDashoffset={-passOffset}
              className="text-bg-pass"
            />
          )}
          {fail > 0 && (
            <circle
              cx={cx}
              cy={cy}
              r={radius}
              fill="none"
              stroke="currentColor"
              strokeWidth={stroke}
              strokeLinecap="butt"
              strokeDasharray={`${failLen} ${circumference - failLen}`}
              strokeDashoffset={-failOffset}
              className="text-bg-fail"
            />
          )}
          {manual > 0 && (
            <circle
              cx={cx}
              cy={cy}
              r={radius}
              fill="none"
              stroke="currentColor"
              strokeWidth={stroke}
              strokeLinecap="butt"
              strokeDasharray={`${manualLen} ${circumference - manualLen}`}
              strokeDashoffset={-manualOffset}
              className="text-bg-warning"
            />
          )}
        </g>
        {/* Center label */}
        <text
          x={cx}
          y={cy - 4}
          textAnchor="middle"
          dominantBaseline="central"
          className={`${centerColorClass} font-mono text-2xl font-bold`}
        >
          {scorePercent}%
        </text>
        <text
          x={cx}
          y={cy + 18}
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-gray-500 font-mono text-[10px] tracking-wider uppercase dark:fill-gray-300"
        >
          {pass}/{total}
        </text>
      </svg>
      <ul className="grid w-full grid-cols-3 gap-2 text-[10px] tracking-wider uppercase">
        <li className="flex flex-col items-center gap-0.5">
          <span className="text-bg-pass font-mono text-base font-bold">
            {pass}
          </span>
          <span className="text-text-neutral-secondary">Pass</span>
        </li>
        <li className="flex flex-col items-center gap-0.5">
          <span className="text-bg-fail font-mono text-base font-bold">
            {fail}
          </span>
          <span className="text-text-neutral-secondary">Fail</span>
        </li>
        <li className="flex flex-col items-center gap-0.5">
          <span className="text-bg-warning font-mono text-base font-bold">
            {manual}
          </span>
          <span className="text-text-neutral-secondary">Manual</span>
        </li>
      </ul>
    </div>
  );
};
