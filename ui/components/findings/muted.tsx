import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

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
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="flex items-center gap-1">
          <MutedIcon className="text-text-neutral-primary size-2" />
          <span className="text-text-neutral-primary text-sm">Muted</span>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <span className="text-xs">{mutedReason}</span>
      </TooltipContent>
    </Tooltip>
  );
};
