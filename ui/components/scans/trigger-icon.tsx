import { Tooltip } from "@heroui/tooltip";
import { Upload } from "lucide-react";

import { ManualIcon, ScheduleIcon } from "@/components/icons";
import type { ScanTrigger } from "@/types";

interface TriggerIconProps {
  trigger: ScanTrigger;
  iconSize?: number;
}

const TRIGGER_LABELS: Record<ScanTrigger, string> = {
  scheduled: "Scheduled",
  manual: "Manual",
  imported: "Imported",
};

export function TriggerIcon({ trigger, iconSize = 24 }: TriggerIconProps) {
  const label = TRIGGER_LABELS[trigger];

  return (
    <Tooltip className="text-xs" content={label}>
      <div className="h-fit">
        {trigger === "scheduled" ? (
          <ScheduleIcon size={iconSize} />
        ) : trigger === "imported" ? (
          <Upload size={iconSize} />
        ) : (
          <ManualIcon size={iconSize} />
        )}
      </div>
    </Tooltip>
  );
}
