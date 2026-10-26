"use client";

import Image from "next/image";

import { getComplianceIcon } from "@/components/icons";
import { Badge, Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { FindingComplianceFramework } from "@/types/compliance-watchlist";

/** Frameworks are not uniquely named — eight AWS ones are called "CIS" — so the
 *  version is part of the label, not decoration. */
export function complianceFrameworkLabel(
  framework: FindingComplianceFramework,
): string {
  const name = framework.framework || framework.name;
  return framework.version ? `${name} ${framework.version}` : name;
}

interface ComplianceFrameworkChipProps {
  framework: FindingComplianceFramework;
  isNavigable: boolean;
  onOpen: (framework: FindingComplianceFramework) => void;
}

export function ComplianceFrameworkChip({
  framework,
  isNavigable,
  onOpen,
}: ComplianceFrameworkChipProps) {
  const icon = getComplianceIcon(framework.complianceId);
  const label = complianceFrameworkLabel(framework);
  const content = icon ? (
    <span className="border-border-neutral-tertiary flex size-7 shrink-0 items-center justify-center rounded-md border bg-slate-50">
      <Image
        src={icon}
        alt={label}
        width={20}
        height={20}
        className="size-5 object-contain"
      />
    </span>
  ) : (
    label
  );

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {isNavigable ? (
          <Button
            type="button"
            variant={icon ? "bare" : "outline"}
            size={icon ? "icon-xs" : "sm"}
            aria-label={`Open ${label} compliance details`}
            onClick={() => onOpen(framework)}
          >
            {content}
          </Button>
        ) : icon ? (
          content
        ) : (
          <Badge variant="tag" size="sm" aria-label={label}>
            {content}
          </Badge>
        )}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

export function buildComplianceDetailHref({
  complianceId,
  framework,
  version,
  scanId,
  regionFilter,
}: {
  complianceId: string;
  framework: string;
  version: string;
  scanId: string;
  regionFilter: string | null;
}): string {
  const params = new URLSearchParams();
  params.set("complianceId", complianceId);
  if (version) {
    params.set("version", version);
  }
  params.set("scanId", scanId);

  if (regionFilter) {
    params.set("filter[region__in]", regionFilter);
  }

  return `/compliance/${encodeURIComponent(framework)}?${params.toString()}`;
}
