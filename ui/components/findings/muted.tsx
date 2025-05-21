import { Tooltip } from "@nextui-org/react";

import { MutedIcon } from "../icons";

interface MutedProps {
  isMuted: boolean;
}

export const Muted = ({ isMuted }: MutedProps) => {
  if (isMuted === false) return null;

  return (
    <Tooltip content={"This finding is muted"} className="text-xs">
      <div className="w-fit rounded-full border border-system-severity-critical/40 p-1">
        <MutedIcon className="h-4 w-4 text-system-severity-critical" />
      </div>
    </Tooltip>
  );
};
