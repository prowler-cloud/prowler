import { Tooltip } from "@heroui/tooltip";

import { MutedIcon } from "../icons";

interface MutedProps {
  isMuted: boolean;
  mutedReason: string;
}

export const Muted = ({
  isMuted,
  mutedReason = "This finding is muted",
}: MutedProps) => {
  if (isMuted === false) return null;

  return (
    <Tooltip content={mutedReason} className="text-xs">
      <div className="border-system-severity-critical/40 w-fit rounded-full border p-1">
        <MutedIcon className="text-system-severity-critical h-4 w-4" />
      </div>
    </Tooltip>
  );
};
