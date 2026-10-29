"use client";

import { ChevronDown } from "lucide-react";
import { useId, useState } from "react";

import { getRealtimeRemediations } from "@/actions/realtime";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import type { RealtimeRemediation } from "@/types/realtime";

interface RemediationItemProps {
  remediation: RealtimeRemediation;
  /** Whether the scope is known (an account is selected). */
  showScope: boolean;
}

export function RemediationItem({
  remediation,
  showScope,
}: RemediationItemProps) {
  const [open, setOpen] = useState(false);
  const { checks, active_checks: active, iam_actions: actions } = remediation;

  return (
    <li className="border-border-neutral-secondary flex flex-col gap-2 rounded-lg border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h5 className="text-text-neutral-primary text-sm font-medium">
          {remediation.title}
        </h5>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={remediation.revertible ? "success" : "warning"}>
            {remediation.revertible ? "Can be undone" : "Cannot be undone"}
          </Badge>
          {showScope && (
            <Badge variant={remediation.in_enforced_scope ? "info" : "outline"}>
              {remediation.in_enforced_scope
                ? `In the enforced frameworks (${active.length} of ${checks.length} checks active)`
                : "Outside the enforced frameworks: never applied"}
            </Badge>
          )}
        </div>
      </div>

      <p className="text-text-neutral-secondary text-sm">
        {remediation.effect}
      </p>

      {remediation.undo && (
        <p className="text-text-neutral-tertiary text-xs">
          {remediation.revertible ? "To undo: " : "Why: "}
          {remediation.undo}
        </p>
      )}

      {checks.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-text-neutral-tertiary text-xs">
            Answers the checks
          </span>
          {checks.map((check) => (
            <Badge
              key={check}
              variant="tag"
              size="sm"
              className={
                showScope && !active.includes(check) ? "opacity-60" : undefined
              }
            >
              {check}
            </Badge>
          ))}
        </div>
      )}

      {actions.length > 0 && (
        <Collapsible open={open} onOpenChange={setOpen}>
          <CollapsibleTrigger asChild>
            <button
              type="button"
              className="text-button-tertiary inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
            >
              <ChevronDown
                aria-hidden="true"
                className={open ? "size-3.5 rotate-180" : "size-3.5"}
              />
              Exact AWS permissions ({actions.length})
            </button>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <ul
              aria-label={`AWS permissions for ${remediation.title}`}
              className="mt-2 flex flex-col gap-0.5"
            >
              {actions.map((action) => (
                <li key={action}>
                  <code className="text-text-neutral-secondary text-xs">
                    {action}
                  </code>
                </li>
              ))}
            </ul>
          </CollapsibleContent>
        </Collapsible>
      )}
    </li>
  );
}

/**
 * What the remediation permission can do, and nothing else. Shown next to the
 * template that creates it, so the person knows what they are granting.
 * Without an account (demo, none yet) the list is the same, with no scope.
 */
export function RemediationList({ providerId }: { providerId?: string }) {
  const headingId = useId();
  const remediations = useRealtimeResource(
    () => getRealtimeRemediations(providerId),
    `remediations:${providerId ?? "none"}`,
  );

  return (
    <section aria-labelledby={headingId} className="flex flex-col gap-3">
      <h4
        id={headingId}
        className="text-text-neutral-primary text-sm font-semibold"
      >
        With this permission Prowler will only be able to:
      </h4>

      {remediations.loading ? (
        <PanelLoading label="Loading the list of fixes" />
      ) : remediations.failure ? (
        <PanelFailure
          failure={remediations.failure}
          onRetry={remediations.reload}
          subject="the list of fixes"
        />
      ) : remediations.data && remediations.data.length > 0 ? (
        <ul className="flex flex-col gap-2">
          {remediations.data.map((remediation) => (
            <RemediationItem
              key={remediation.id}
              remediation={remediation}
              showScope={Boolean(providerId)}
            />
          ))}
        </ul>
      ) : (
        <PanelEmpty title="No fixes are available yet" />
      )}

      <p className="text-text-neutral-tertiary max-w-prose text-xs">
        Nothing outside this list is ever fixed automatically. A fix acts only
        on the resource named in the event that triggered it. With dry run on,
        Prowler records what it would change instead of changing it. Every fix
        is audited: what changed, when, and how to undo it.
      </p>
    </section>
  );
}
