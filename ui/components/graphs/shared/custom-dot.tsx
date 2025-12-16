import { Dot } from "recharts";

interface CustomDotProps {
  cx?: number;
  cy?: number;
  color: string;
  isFaded: boolean;
}

export const CustomDot = ({ cx, cy, color, isFaded }: CustomDotProps) => {
  if (cx === undefined || cy === undefined) return null;

  return <Dot cx={cx} cy={cy} r={4} fill={color} opacity={isFaded ? 0.2 : 1} />;
};
