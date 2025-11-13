import {
  SidebarCollapseIcon,
  SidebarExpandIcon,
} from "@/components/icons/Icons";

import { Button } from "../button/button";

interface SidebarToggleProps {
  isOpen: boolean | undefined;
  setIsOpen?: () => void;
}

export function SidebarToggle({ isOpen, setIsOpen }: SidebarToggleProps) {
  return (
    <Button
      onClick={() => setIsOpen?.()}
      className="h-8 w-8 rounded-md"
      variant="outline"
      size="icon"
    >
      {isOpen === false ? (
        <SidebarCollapseIcon className="h-5 w-5" />
      ) : (
        <SidebarExpandIcon className="h-5 w-5" />
      )}
    </Button>
  );
}
