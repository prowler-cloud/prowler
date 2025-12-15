export const AXIS_FONT_SIZE = 14;
const TODAY_FONT_SIZE = 12;
const MONTH_FONT_SIZE = 11;

interface CustomXAxisTickProps {
  x: number;
  y: number;
  index?: number;
  payload: {
    value: string | number;
  };
  visibleTicksCount?: number;
}

const getTodayISO = () => {
  const today = new Date();
  return today.toISOString().split("T")[0];
};

const getMonthName = (dateStr: string) => {
  const date = new Date(dateStr);
  return date.toLocaleDateString("en-US", { month: "short" });
};

const getDayNumber = (dateStr: string) => {
  const date = new Date(dateStr);
  return date.getDate();
};

const getMonthFromDate = (dateStr: string) => {
  const date = new Date(dateStr);
  return date.getMonth();
};

export const CustomXAxisTickWithToday = Object.assign(
  function CustomXAxisTickWithToday(
    props: CustomXAxisTickProps & { data?: Array<{ date: string }> },
  ) {
    const { x, y, payload, index = 0, data = [] } = props;
    const dateStr = String(payload.value);
    const todayISO = getTodayISO();
    const isToday = dateStr === todayISO;

    const dayNumber = getDayNumber(dateStr);
    const currentMonth = getMonthFromDate(dateStr);

    // Show month name if it's the first tick or if the month changed from previous tick
    const isFirstTick = index === 0;
    const previousDate = index > 0 && data[index - 1]?.date;
    const previousMonth = previousDate ? getMonthFromDate(previousDate) : -1;
    const monthChanged = currentMonth !== previousMonth;
    const showMonth = isFirstTick || monthChanged;

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
          {dayNumber}
        </text>
        {showMonth && (
          <text
            x={0}
            y={42}
            textAnchor="middle"
            fill="var(--color-text-neutral-tertiary)"
            fontSize={MONTH_FONT_SIZE}
          >
            {getMonthName(dateStr)}
          </text>
        )}
        {isToday && (
          <text
            x={0}
            y={showMonth ? 56 : 42}
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
