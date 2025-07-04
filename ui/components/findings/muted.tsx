import { Tooltip } from "@nextui-org/react";

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
      <div className="w-fit rounded-full border border-system-severity-critical/40 p-1">
        <MutedIcon className="h-4 w-4 text-system-severity-critical" />
      </div>
    </Tooltip>
  );
};
