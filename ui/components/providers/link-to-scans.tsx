interface LinkToScansProps {
  hasSchedule: boolean;
}

export const LinkToScans = ({ hasSchedule }: LinkToScansProps) => {
  return (
    <span className="text-text-neutral-secondary text-sm">
      {hasSchedule ? "Daily" : "None"}
    </span>
  );
};
