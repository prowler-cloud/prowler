export const AXIS_FONT_SIZE = 14;
const TODAY_FONT_SIZE = 12;

interface CustomXAxisTickProps {
  x: number;
  y: number;
  payload: {
    value: string | number;
  };
}

const getTodayFormatted = () => {
  const today = new Date();
  return today.toLocaleDateString("en-US", {
    month: "2-digit",
    day: "2-digit",
  });
};

export const CustomXAxisTickWithToday = Object.assign(
  function CustomXAxisTickWithToday(props: CustomXAxisTickProps) {
    const { x, y, payload } = props;
    const todayFormatted = getTodayFormatted();
    const isToday = String(payload.value) === todayFormatted;

    return (
      <g transform={`translate(${x},${y})`}>
        <text
          x={0}
          y={20}
          dy={4}
          textAnchor="middle"
          fill="var(--color-text-neutral-secondary)"
          fontSize={AXIS_FONT_SIZE}
        >
          {payload.value}
        </text>
        {isToday && (
          <text
            x={0}
            y={36}
            textAnchor="middle"
            fill="var(--color-text-neutral-secondary)"
            fontSize={TODAY_FONT_SIZE}
            fontWeight={400}
          >
            (today)
          </text>
        )}
      </g>
    );
  },
  { displayName: "CustomXAxisTickWithToday" },
);

export const CustomXAxisTick = Object.assign(
  function CustomXAxisTick(props: CustomXAxisTickProps) {
    const { x, y, payload } = props;
    return (
      <g transform={`translate(${x},${y})`}>
        <text
          x={0}
          y={20}
          dy={4}
          textAnchor="middle"
          fill="var(--color-text-neutral-secondary)"
          fontSize={AXIS_FONT_SIZE}
        >
          {payload.value}
        </text>
      </g>
    );
  },
  { displayName: "CustomXAxisTick" },
);
