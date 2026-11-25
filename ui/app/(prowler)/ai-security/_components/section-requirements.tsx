"use client";

import Link from "next/link";
import { use } from "react";

import { aiFindingsHref } from "@/app/(prowler)/ai-security/_lib/findings";
import type {
  AiRequirement,
  AiRequirementCheck,
} from "@/app/(prowler)/ai-security/_types";
import { Badge, Button, Skeleton } from "@/components/shadcn";
import { REQUIREMENT_STATUS, type RequirementStatus } from "@/types/compliance";

const STATUS_BADGE: Record<
  RequirementStatus,
  { label: string; variant: "success" | "error" | "tag" }
> = {
  [REQUIREMENT_STATUS.PASS]: { label: "Pass", variant: "success" },
  [REQUIREMENT_STATUS.FAIL]: { label: "Fail", variant: "error" },
  [REQUIREMENT_STATUS.MANUAL]: { label: "Manual", variant: "tag" },
  [REQUIREMENT_STATUS.NO_FINDINGS]: { label: "No findings", variant: "tag" },
};

const StatusBadge = ({ status }: { status: RequirementStatus }) => (
  <Badge size="sm" variant={STATUS_BADGE[status].variant}>
    {STATUS_BADGE[status].label}
  </Badge>
);

function Check({
  check,
  providerTypes,
}: {
  check: AiRequirementCheck;
  providerTypes: string;
}) {
  return (
    <li className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
      <span className="flex min-w-0 flex-1 basis-48 flex-col">
        <span className="text-text-neutral-primary truncate text-xs">
          {check.title}
        </span>
        <span className="text-text-neutral-tertiary truncate font-mono text-xs">
          {check.id}
        </span>
      </span>
      <StatusBadge status={check.status} />
      {check.status === REQUIREMENT_STATUS.FAIL && (
        <Button asChild variant="link" size="link-sm">
          <Link
            href={aiFindingsHref({
              "filter[check_id__in]": check.id,
              "filter[provider_type__in]": providerTypes,
            })}
          >
            {check.failedResources.toLocaleString()} failed{" "}
            {check.failedResources === 1 ? "resource" : "resources"}
          </Link>
        </Button>
      )}
    </li>
  );
}

interface SectionRequirementsProps {
  requirements: Promise<AiRequirement[] | null>;
  /** The provider types in scope, comma-separated, for the Findings links. */
  providerTypes: string;
}

/** A framework section's requirements and the latest result of each check. */
export function SectionRequirements({
  requirements,
  providerTypes,
}: SectionRequirementsProps) {
  const loaded = use(requirements);

  if (!loaded) {
    return (
      <p className="text-text-error-primary text-xs">
        The checks could not be loaded. Collapse and expand to try again.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {loaded.map((requirement) => (
        <li key={requirement.id} className="flex flex-col gap-1.5">
          <p className="flex items-baseline gap-2 text-sm">
            <span className="text-text-neutral-secondary shrink-0 font-mono text-xs">
              {requirement.id}
            </span>
            <span className="text-text-neutral-primary min-w-0 flex-1">
              {requirement.name}
            </span>
            <StatusBadge status={requirement.status} />
          </p>
          {requirement.checks.length === 0 ? (
            <p className="text-text-neutral-tertiary text-xs">
              Needs a manual review. {requirement.description}
            </p>
          ) : (
            <ul className="flex flex-col gap-2" aria-label="Checks">
              {requirement.checks.map((check) => (
                <Check
                  key={check.id}
                  check={check}
                  providerTypes={providerTypes}
                />
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  );
}

export const SectionRequirementsSkeleton = () => (
  <div className="flex flex-col gap-2" aria-busy>
    <Skeleton className="h-4 w-3/4" />
    <Skeleton className="h-4 w-1/2" />
    <Skeleton className="h-4 w-2/3" />
  </div>
);
