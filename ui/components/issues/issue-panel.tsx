"use client";

import Link from "next/link";

import { IssueTriage } from "@/components/issues/issue-triage";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { EntityInfo } from "@/components/shadcn/entities";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { SeverityBadge } from "@/components/shadcn/table/severity-badge";
import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";
import {
  LEG_LABELS,
  LEG_QUESTIONS,
  LEG_STATE_LABELS,
  legBadgeVariant,
  VERDICTS,
} from "@/lib/issues/verdicts";
import {
  ATTACKER_START_LABEL,
  ISSUE_OUTCOME_LABEL,
  IssueResource,
  LegName,
} from "@/types/issues";

interface IssuePanelProps {
  issue: IssueResource;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * The verdict and the reasoning behind it, from the list row alone (no
 * fetch). Graph, resources, findings and compliance stay on the issue page.
 */
export const IssuePanel = ({ issue, open, onOpenChange }: IssuePanelProps) => {
  const { attributes } = issue;
  const verdict = VERDICTS.find((item) => item.id === attributes.verdict);
  const scanId = issue.relationships?.scan?.data?.id;

  return (
    <DetailSidePanel
      open={open}
      onOpenChange={onOpenChange}
      title={attributes.title}
      description="Why this issue got its verdict and how to fix it"
    >
      <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-6 overflow-y-auto">
        <header className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-3">
            <Badge variant={verdict?.variant ?? "tag"}>
              {verdict?.label ?? attributes.verdict}
            </Badge>
            <SeverityBadge severity={attributes.severity} />
          </div>
          <h3 className="text-text-neutral-primary text-lg font-semibold break-words">
            {attributes.title}
          </h3>
          <EntityInfo
            cloudProvider={attributes.cloud}
            entityAlias={attributes.account}
          />
          <p className="text-text-neutral-tertiary text-xs break-all">
            {attributes.findings_count.toLocaleString()}{" "}
            {attributes.findings_count === 1 ? "finding" : "findings"} ·{" "}
            {attributes.pattern}
          </p>
        </header>

        {attributes.attacker_start && attributes.outcome && (
          <div className="grid grid-cols-2 gap-3">
            <InfoField label="Starts from">
              {ATTACKER_START_LABEL[attributes.attacker_start]}
            </InfoField>
            <InfoField label="Leads to">
              {ISSUE_OUTCOME_LABEL[attributes.outcome]}
            </InfoField>
          </div>
        )}

        <section aria-label="Exploitability assessment">
          <h4 className="mb-1 text-sm font-semibold">
            Exploitability assessment
          </h4>
          <ul className="divide-border-neutral-secondary flex flex-col divide-y">
            {(Object.keys(LEG_LABELS) as LegName[]).map((name) => {
              const leg = attributes.legs[name];
              if (!leg) return null;
              return (
                <li key={name} className="flex items-start gap-3 py-3">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="text-sm font-medium">
                      {LEG_LABELS[name]}
                    </span>
                    <span className="text-text-neutral-tertiary text-xs">
                      {LEG_QUESTIONS[name]}
                    </span>
                    <span className="text-text-neutral-secondary text-sm">
                      {leg.text}
                    </span>
                  </div>
                  <Badge variant={legBadgeVariant(name, leg.state)}>
                    {LEG_STATE_LABELS[leg.state]}
                  </Badge>
                </li>
              );
            })}
          </ul>
        </section>

        <section aria-label="Remediation" className="flex flex-col gap-2">
          <h4 className="text-sm font-semibold">Remediation</h4>
          <p className="text-text-neutral-secondary text-sm">
            {attributes.fix}
          </p>
          {scanId && (
            <Button
              asChild
              variant="link"
              size="link-sm"
              className="self-start"
            >
              <Link
                href={`/findings?${new URLSearchParams({ "filter[scan__in]": scanId, "filter[status__in]": "FAIL" })}`}
              >
                Open this scan&apos;s failed findings
              </Link>
            </Button>
          )}
        </section>

        <IssueTriage
          key={`${issue.id}-${attributes.updated_at}`}
          id={issue.id}
          status={attributes.triage_status}
        />

        <Button asChild className="self-start">
          <Link href={`/issues/${issue.id}`}>Open the full path</Link>
        </Button>
      </div>
    </DetailSidePanel>
  );
};
