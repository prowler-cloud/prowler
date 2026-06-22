import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

interface SidebarToggleProps {
  isOpen: boolean | undefined;
  setIsOpen?: () => void;
}

export function SidebarToggle({ isOpen, setIsOpen }: SidebarToggleProps) {
  // Closed → chevron right (will open); open/undefined → chevron left (will collapse).
  const isClosed = isOpen === false;
  const Chevron = isClosed ? ChevronRight : ChevronLeft;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="bare"
          size="icon-sm"
          onClick={() => setIsOpen?.()}
          aria-label={isClosed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <Chevron className="size-5" />
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom">
        {isClosed ? "Expand Sidebar" : "Collapse Sidebar"}
      </TooltipContent>
    </Tooltip>
  );
}
