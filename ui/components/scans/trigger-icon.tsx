import { Tooltip } from "@nextui-org/react";

import { ManualIcon, ScheduleIcon } from "@/components/icons";

interface TriggerIconProps {
  trigger: "scheduled" | "manual";
  iconSize?: number;
}

export function TriggerIcon({ trigger, iconSize = 24 }: TriggerIconProps) {
  return (
    <Tooltip
      className="text-xs"
      content={trigger === "scheduled" ? "Scheduled" : "Manual"}
    >
      <div className="h-fit">
        {trigger === "scheduled" ? (
          <ScheduleIcon size={iconSize} />
        ) : (
          <ManualIcon size={iconSize} />
        )}
      </div>
    </Tooltip>
  );
}
