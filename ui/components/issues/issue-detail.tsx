"use client";

import { Send } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { IssueCompliance } from "@/components/issues/issue-compliance";
import { IssueFindings } from "@/components/issues/issue-findings";
import { IssueGraph } from "@/components/issues/issue-graph";
import { IssueTriage } from "@/components/issues/issue-triage";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { CodeSnippet } from "@/components/shadcn/code-snippet";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { useIssueEvidence } from "@/hooks/use-issue-evidence";
import { riskFactors } from "@/lib/issues/risk-factors";
import {
  LEG_LABELS,
  LEG_QUESTIONS,
  LEG_STATE_LABELS,
  legBadgeVariant,
} from "@/lib/issues/verdicts";
import { createJiraDispatchPayload } from "@/lib/jira-dispatch-selection";
import { useJiraDispatchStore } from "@/store/jira-dispatch/store";
import { JIRA_DISPATCH_TARGET } from "@/types/integrations";
import {
  ATTACKER_START_LABEL,
  ISSUE_OUTCOME_LABEL,
  IssueAttributes,
  LegName,
} from "@/types/issues";

const RESOURCE_PAGE_SIZE = 12;

// The issue carries resource uids, not ids, so this opens the Resources list
// on that one resource rather than its drawer.
const resourceHref = (uid: string, providerId?: string) =>
  `/resources?${new URLSearchParams({
    "filter[uid]": uid,
    // A uid is unique within an account, not across them.
    ...(providerId && { "filter[provider_id__in]": providerId }),
  })}`;

interface IssueDetailProps {
  id: string;
  issue: IssueAttributes;
  scanId?: string;
  providerId?: string;
}

export const IssueDetail = ({
  id,
  issue,
  scanId,
  providerId,
}: IssueDetailProps) => {
  const openJiraDispatch = useJiraDispatchStore(
    (state) => state.openJiraDispatch,
  );
  const [visibleResources, setVisibleResources] = useState(RESOURCE_PAGE_SIZE);
  const { state, retry } = useIssueEvidence(id, scanId, providerId);
  const activeScanId = state.status === "loaded" ? state.scanId : scanId;
  const factors = riskFactors(issue);
  const uniqueFindings =
    state.status === "loaded"
      ? Array.from(
          new Map(
            state.findings?.map((finding) => [finding.id, finding]),
          ).values(),
        )
      : [];
  const jiraPayload = createJiraDispatchPayload({
    findingTitle: issue.title,
    targetIds: uniqueFindings.map((finding) => finding.id),
    targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
    description: `Send ${uniqueFindings.length} of ${issue.findings_count} findings on this attack path.`,
  });

  return (
    <div className="flex min-w-0 flex-col gap-4 py-4">
      {/* The conditions that hold at once: the verdict says how bad, these
          say why, and which part to argue with. */}
      {factors.length > 0 && (
        <ul aria-label="Risk factors" className="flex flex-wrap gap-1.5">
          {factors.map((factor) => (
            <li key={factor.label}>
              <Badge variant={factor.variant} title={factor.title}>
                {factor.label}
              </Badge>
            </li>
          ))}
        </ul>
      )}
      {state.status === "loaded" && state.findings === undefined && (
        <IssuesLoadError
          message="Could not load the findings for this issue."
          onRetry={retry}
        />
      )}
      {state.status === "loaded" &&
        state.findings !== undefined &&
        state.resources.length > 0 && (
          <IssueGraph
            issue={issue}
            resourceUids={state.resources}
            findings={state.findings}
            {...(state.providerId && state.scanId
              ? { providerId: state.providerId, scanId: state.scanId }
              : { providerId: undefined, scanId: undefined })}
          />
        )}
      {issue.outcome && issue.attacker_start && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <InfoField label="Outcome">
            {ISSUE_OUTCOME_LABEL[issue.outcome]}
          </InfoField>
          {/* Inline, not an InfoTooltip: its trigger has no tab stop. */}
          <InfoField label="Starts from">
            {ATTACKER_START_LABEL[issue.attacker_start]}
            <p className="text-text-neutral-tertiary text-xs">
              Where the attacker has to be standing. Whether they also need a
              credential is the Access leg.
            </p>
          </InfoField>
        </div>
      )}
      <section aria-label="Exploitability assessment">
        <h4 className="mb-3 text-sm font-semibold">
          Exploitability assessment
        </h4>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {(Object.keys(LEG_QUESTIONS) as LegName[]).map((name) => {
            const leg = issue.legs[name];
            if (!leg) return null;
            return (
              <Card key={name} variant="inner" className="min-w-0 gap-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h5 className="text-sm font-medium">{LEG_LABELS[name]}</h5>
                  <Badge variant={legBadgeVariant(name, leg.state)}>
                    {LEG_STATE_LABELS[leg.state]}
                  </Badge>
                </div>
                <p className="text-text-neutral-tertiary text-xs">
                  {LEG_QUESTIONS[name]}
                </p>
                <p className="text-text-neutral-secondary text-sm">
                  {leg.text}
                </p>
                {leg.evidence.length > 0 && (
                  <ul className="flex flex-col gap-1">
                    {leg.evidence.map((line) => (
                      <li key={line}>
                        <CodeSnippet
                          value={line}
                          multiline
                          hideCopyButton
                          transparent
                        />
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            );
          })}
        </div>
      </section>
      {state.status === "loading" ? (
        <p role="status" className="text-text-neutral-tertiary text-sm">
          Loading issue details…
        </p>
      ) : state.status === "error" ? (
        <IssuesLoadError
          message="Could not load the resources for this issue."
          onRetry={retry}
        />
      ) : state.resources.length > 0 ? (
        <section aria-label="Affected resources">
          <h4 className="mb-3 text-sm font-semibold">
            Affected resources ({state.resources.length})
          </h4>
          <ul className="flex flex-col gap-2">
            {state.resources.slice(0, visibleResources).map((uid) => (
              <li
                key={uid}
                className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1"
              >
                <CodeSnippet value={uid} multiline ariaLabel={`Copy ${uid}`} />
                <Button asChild variant="link" size="link-sm">
                  <Link
                    href={resourceHref(uid, state.providerId)}
                    aria-label={`Open in Resources: ${uid}`}
                  >
                    Open in Resources
                  </Link>
                </Button>
              </li>
            ))}
          </ul>
          {visibleResources < state.resources.length && (
            <Button
              variant="link"
              size="link-sm"
              onClick={() =>
                setVisibleResources((value) => value + RESOURCE_PAGE_SIZE)
              }
            >
              Show more resources
            </Button>
          )}
          {visibleResources > RESOURCE_PAGE_SIZE && (
            <Button
              variant="link"
              size="link-sm"
              onClick={() => setVisibleResources(RESOURCE_PAGE_SIZE)}
            >
              Show fewer resources
            </Button>
          )}
        </section>
      ) : null}
      <section aria-label="Remediation">
        <h4 className="mb-3 text-sm font-semibold">Remediation</h4>
        <p className="text-text-neutral-secondary text-sm">{issue.fix}</p>
        <div className="flex flex-wrap items-center gap-3">
          {activeScanId && (
            <Button asChild variant="link" size="link-sm">
              <Link
                href={`/findings?${new URLSearchParams({ "filter[scan__in]": activeScanId, "filter[status__in]": "FAIL" })}`}
              >
                Open this scan&apos;s failed findings
              </Link>
            </Button>
          )}
          {jiraPayload && (
            // shortcut: the ticket groups the loaded preview (ISSUE_FINDINGS_LIMIT
            // findings), not every finding of a larger issue; page through
            // finding_uids if tickets for big issues need all of them.
            <Button
              variant="outline"
              size="sm"
              onClick={() => openJiraDispatch(jiraPayload)}
            >
              <Send aria-hidden="true" />
              Send to Jira
            </Button>
          )}
        </div>
      </section>
      {state.status === "loaded" &&
        state.findings &&
        state.findings.length > 0 && (
          <IssueFindings
            findings={uniqueFindings}
            scanId={activeScanId}
            total={issue.findings_count}
          />
        )}
      {state.status === "loaded" &&
        state.findings &&
        state.findings.length > 0 && (
          <IssueCompliance
            findings={state.findings}
            scanId={activeScanId}
            truncated={state.findingsTruncated}
          />
        )}
      <IssueTriage id={id} status={issue.triage_status} />
    </div>
  );
};
