import type { ReactNode } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { InfoTooltip } from "@/components/shadcn/info-field/info-field";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";

interface ComplianceAccordionRequirementTitleProps {
  type: string;
  name: string;
  status: FindingStatus;
  invalidConfig?: boolean;
  statusContent?: ReactNode;
}

export const ComplianceAccordionRequirementTitle = ({
  type,
  name,
  status,
  invalidConfig = false,
  statusContent,
}: ComplianceAccordionRequirementTitleProps) => {
  return (
    <div className="flex w-full items-center justify-between gap-2">
      <div className="flex w-5/6 items-center gap-2">
        {type && (
          <Badge variant="tag" size="sm">
            {type}
          </Badge>
        )}
        <span>{name}</span>
        {invalidConfig && <InfoTooltip content={INVALID_CONFIG_NOTE} />}
      </div>
      {statusContent ?? <StatusFindingBadge status={status} />}
    </div>
  );
};
