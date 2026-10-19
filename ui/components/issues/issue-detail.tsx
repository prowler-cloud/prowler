"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { getIssue, getIssueFindings } from "@/actions/issues";
import { IssueGraph } from "@/components/issues/issue-graph";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { CodeSnippet } from "@/components/shadcn/code-snippet";
import { legBadgeVariant } from "@/lib/issues/verdicts";
import {
  IssueAttributes,
  IssueFinding,
  LegName,
  LegState,
} from "@/types/issues";

const LEG_QUESTIONS: Record<LegName, string> = {
  reachability: "Can an attacker reach it?",
  access: "Can an attacker authenticate or bypass authentication?",
  target: "Is there a target worth reaching?",
  controls: "Are protective controls in place?",
  verification: "Would the activity be detected?",
};
const LEG_LABELS: Record<LegName, string> = {
  reachability: "Reachability",
  access: "Access",
  target: "Target",
  controls: "Controls",
  verification: "Verification",
};
const STATE_LABELS: Record<LegState, string> = {
  yes: "Yes",
  no: "No",
  partial: "Partly",
  unknown: "Unknown",
};
const RESOURCE_PAGE_SIZE = 12;

interface IssueDetailProps {
  id: string;
  issue: IssueAttributes;
  scanId?: string;
  providerId?: string;
}

type ResourcesState =
  | { status: "loading" }
  | { status: "error" }
  | {
      status: "loaded";
      resources: string[];
      findings: IssueFinding[] | undefined;
      scanId?: string;
      providerId?: string;
    };

export const IssueDetail = ({
  id,
  issue,
  scanId,
  providerId,
}: IssueDetailProps) => {
  const [visibleResources, setVisibleResources] = useState(RESOURCE_PAGE_SIZE);
  const [attempt, setAttempt] = useState(0);
  // Resource UIDs are only included by the detail endpoint, fetched on expansion.
  const [state, setState] = useState<ResourcesState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    getIssue(id)
      .then(async (detail) => {
        if (cancelled) return;
        const attributes = detail?.data?.attributes;
        if (!attributes?.resource_uids) {
          setState({ status: "error" });
          return;
        }
        const detailScanId =
          detail?.data.relationships?.scan?.data?.id ?? scanId;
        const detailProviderId =
          detail?.data.relationships?.provider?.data?.id ?? providerId;
        const findingUids = attributes.finding_uids ?? [];
        const findings = detailScanId
          ? await getIssueFindings(detailScanId, findingUids)
          : findingUids.length === 0
            ? []
            : undefined;
        if (!cancelled)
          setState({
            status: "loaded",
            resources: attributes.resource_uids,
            findings,
            scanId: detailScanId,
            providerId: detailProviderId,
          });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "error" });
      });
    return () => {
      cancelled = true;
    };
  }, [id, scanId, providerId, attempt]);

  const retry = () => {
    setState({ status: "loading" });
    setAttempt((value) => value + 1);
  };
  const activeScanId = state.status === "loaded" ? state.scanId : scanId;

  return (
    <div className="flex min-w-0 flex-col gap-4 py-4">
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
                    {STATE_LABELS[leg.state]}
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
              <li key={uid} className="min-w-0">
                <CodeSnippet value={uid} multiline ariaLabel={`Copy ${uid}`} />
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
        {activeScanId && (
          <Button asChild variant="link" size="link-sm">
            <Link
              href={`/findings?${new URLSearchParams({ "filter[scan__in]": activeScanId, "filter[status__in]": "FAIL" })}`}
            >
              Open this scan&apos;s failed findings
            </Link>
          </Button>
        )}
      </section>
    </div>
  );
};
