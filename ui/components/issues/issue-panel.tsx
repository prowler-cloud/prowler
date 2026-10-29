"use client";

import { ArrowLeft, Box, Tag } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { JiraDispatchActionItem } from "@/components/findings/jira-dispatch-action-item";
import { MarkdownContainer } from "@/components/findings/markdown-container";
import { FindingDetailDrawer } from "@/components/findings/table";
import { IssueAttackPath } from "@/components/issues/issue-attack-path";
import { IssueCompliance } from "@/components/issues/issue-compliance";
import { IssueFindings } from "@/components/issues/issue-findings";
import { IssueResources } from "@/components/issues/issue-resources";
import { IssueTriage } from "@/components/issues/issue-triage";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import {
  BreadcrumbNavigation,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import { CodeSnippet } from "@/components/shadcn/code-snippet";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { EntityInfo } from "@/components/shadcn/entities";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { LoadingState } from "@/components/shadcn/spinner/loading-state";
import { SeverityBadge } from "@/components/shadcn/table/severity-badge";
import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";
import { useFindingDetails } from "@/hooks/use-finding-details";
import {
  LEG_LABELS,
  LEG_QUESTIONS,
  LEG_STATE_LABELS,
  legBadgeVariant,
  VERDICTS,
} from "@/lib/issues/verdicts";
import { buildJiraActionLabel } from "@/lib/jira-dispatch-action";
import { createJiraDispatchPayload } from "@/lib/jira-dispatch-selection";
import { JIRA_DISPATCH_TARGET } from "@/types/integrations";
import {
  ATTACKER_START_LABEL,
  ISSUE_OUTCOME_LABEL,
  IssueResource,
  LegName,
} from "@/types/issues";

import { useIssueEvidence } from "./use-issue-evidence";

const ISSUE_PANEL_TAB = {
  EXPLOITABILITY: "exploitability",
  ATTACK_PATH: "attack-path",
  FINDINGS: "findings",
  RESOURCES: "resources",
  REMEDIATION: "remediation",
  TRIAGE: "triage",
} as const;

type IssuePanelTab = (typeof ISSUE_PANEL_TAB)[keyof typeof ISSUE_PANEL_TAB];

const ISSUE_PANEL_TABS: { id: IssuePanelTab; label: string }[] = [
  { id: ISSUE_PANEL_TAB.EXPLOITABILITY, label: "Exploitability" },
  { id: ISSUE_PANEL_TAB.ATTACK_PATH, label: "Attack path" },
  { id: ISSUE_PANEL_TAB.FINDINGS, label: "Findings" },
  { id: ISSUE_PANEL_TAB.RESOURCES, label: "Resources" },
  { id: ISSUE_PANEL_TAB.REMEDIATION, label: "Remediation" },
  { id: ISSUE_PANEL_TAB.TRIAGE, label: "Triage" },
];

interface IssuePanelProps {
  issue: IssueResource;
  /** The provider's account uid, which the issue itself does not carry. */
  providerUid?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/** Everything about one issue, including drilling into its findings. */
export const IssuePanel = ({
  issue,
  providerUid,
  open,
  onOpenChange,
}: IssuePanelProps) => (
  <DetailSidePanel
    open={open}
    onOpenChange={onOpenChange}
    title={issue.attributes.title}
    description="The issue's verdict, attack path, evidence, fix and triage"
  >
    {/* Mounted only while open, so the evidence loads when someone looks. */}
    <IssuePanelContent issue={issue} providerUid={providerUid} />
  </DetailSidePanel>
);

const IssuePanelContent = ({
  issue,
  providerUid,
}: Pick<IssuePanelProps, "issue" | "providerUid">) => {
  const router = useRouter();
  const { attributes } = issue;
  const verdict = VERDICTS.find((item) => item.id === attributes.verdict);
  const scanId = issue.relationships?.scan?.data?.id;
  const providerId = issue.relationships?.provider?.data?.id;
  const {
    state: evidence,
    retry,
    refresh,
  } = useIssueEvidence(issue.id, scanId, providerId);
  // Controlled so closing a finding returns to the tab it was opened from.
  const [tab, setTab] = useState<IssuePanelTab>(ISSUE_PANEL_TAB.EXPLOITABILITY);
  const [openFindingId, setOpenFindingId] = useState<string | null>(null);
  const finding = useFindingDetails();

  const activeScanId = evidence.status === "loaded" ? evidence.scanId : scanId;
  const scanFindingsHref =
    activeScanId &&
    `/findings?${new URLSearchParams({ "filter[scan__in]": activeScanId, "filter[status__in]": "FAIL" })}`;
  const loadedFindings =
    evidence.status === "loaded" ? evidence.findings : undefined;
  // The findings request returns one row per finding and resource.
  const uniqueFindings = Array.from(
    new Map(loadedFindings?.map((item) => [item.id, item])).values(),
  );
  // shortcut: the ticket groups the loaded preview (ISSUE_FINDINGS_LIMIT
  // findings), not every finding of a larger issue; page through finding_uids
  // if tickets for big issues need all of them.
  const jiraPayload = createJiraDispatchPayload({
    findingTitle: attributes.title,
    targetIds: uniqueFindings.map((item) => item.id),
    targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
    description: `Send ${uniqueFindings.length} of ${attributes.findings_count} findings on this attack path.`,
  });

  const openFinding = (findingId: string) => {
    setOpenFindingId(findingId);
    void finding.navigateToFinding(findingId);
  };
  const closeFinding = () => {
    setOpenFindingId(null);
    finding.resetFindingDetails();
    // The finding may have been triaged or muted while open.
    refresh();
  };

  // A finding opens in place, like a resource's findings do: a second detail
  // view would take the side panel over and close this issue.
  if (openFindingId) {
    return (
      <div className="flex h-full min-h-0 flex-col gap-4">
        <BreadcrumbNavigation
          mode="custom"
          customItems={[
            {
              name: "Issue details",
              icon: <ArrowLeft />,
              isClickable: true,
              onClick: closeFinding,
            },
            {
              name: finding.findingDetailLoading
                ? "Loading..."
                : (finding.findingDetails?.attributes?.check_metadata
                    ?.checktitle ?? "Finding Detail"),
              isLast: true,
            },
          ]}
        />
        {finding.findingDetailLoading ? (
          <LoadingState label="Loading finding details..." />
        ) : finding.findingDetails ? (
          // The detail scrolls inside itself, so it needs a bounded height.
          <div className="min-h-0 flex-1">
            <FindingDetailDrawer
              key={finding.findingDetails.id}
              finding={finding.findingDetails}
              inline
            />
          </div>
        ) : (
          <IssuesLoadError
            message="Could not load this finding."
            onRetry={() => openFinding(openFindingId)}
          />
        )}
      </div>
    );
  }

  const evidencePending =
    evidence.status === "loading" ? (
      <p role="status" className="text-text-neutral-tertiary text-sm">
        Loading issue details…
      </p>
    ) : null;

  return (
    <div className="flex h-full min-w-0 flex-col gap-4 overflow-hidden">
      <header className="flex flex-col gap-2">
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <Badge variant={verdict?.variant ?? "tag"}>
              {verdict?.label ?? attributes.verdict}
            </Badge>
            <SeverityBadge severity={attributes.severity} />
          </div>
          {/* Same actions menu as the resource and finding panels. Jira joins
              once the findings it sends have loaded. */}
          <div className="shrink-0">
            {scanFindingsHref || jiraPayload ? (
              <ActionDropdown variant="bordered" ariaLabel="Issue actions">
                {scanFindingsHref && (
                  <ActionDropdownItem
                    icon={<Tag className="size-5" />}
                    label="Open this scan's failed findings"
                    onSelect={() => router.push(scanFindingsHref)}
                  />
                )}
                <JiraDispatchActionItem
                  label={buildJiraActionLabel({
                    findingCount: uniqueFindings.length,
                  })}
                  payload={jiraPayload}
                />
              </ActionDropdown>
            ) : (
              evidence.status === "loading" && (
                <Skeleton className="size-8 rounded-md" />
              )
            )}
          </div>
        </div>
        <h3 className="text-text-neutral-primary line-clamp-2 text-lg leading-tight font-medium">
          {attributes.title}
        </h3>
        {/* Under the title, like the finding panel's frameworks. */}
        {evidence.status === "loading" ? (
          <div aria-hidden="true" className="flex flex-col gap-1.5">
            <Skeleton className="h-4 w-28 rounded" />
            <div className="flex flex-wrap items-center gap-2">
              <Skeleton className="size-7 rounded-md" />
              <Skeleton className="size-7 rounded-md" />
              <Skeleton className="size-7 rounded-md" />
            </div>
          </div>
        ) : (
          loadedFindings &&
          loadedFindings.length > 0 && (
            <IssueCompliance
              findings={loadedFindings}
              scanId={activeScanId}
              truncated={
                evidence.status === "loaded" && evidence.findingsTruncated
              }
            />
          )
        )}
        {/* The finding panel's Provider / Service / Region row. */}
        <div
          data-responsive-container
          className="@container mt-2 flex min-w-0 flex-col"
        >
          <div className="grid min-w-0 grid-cols-2 gap-4 @md:grid-cols-[minmax(0,1fr)_minmax(0,0.55fr)_minmax(0,1fr)] @md:gap-x-8">
            <div className="col-span-2 flex min-w-0 flex-col gap-1 @md:col-span-1">
              <span className="text-text-neutral-secondary text-[10px] whitespace-nowrap">
                Provider
              </span>
              <EntityInfo
                cloudProvider={attributes.cloud}
                nameIcon={<Box className="size-4" />}
                entityAlias={attributes.account}
                entityId={providerUid}
              />
            </div>
            <InfoField label="Findings" variant="compact" className="min-w-0">
              <span className="block truncate whitespace-nowrap">
                {attributes.findings_count.toLocaleString()}
              </span>
            </InfoField>
            <InfoField label="Pattern" variant="compact" className="min-w-0">
              <span
                className="block truncate whitespace-nowrap"
                title={attributes.pattern}
              >
                {attributes.pattern}
              </span>
            </InfoField>
          </div>
        </div>
      </header>

      <Tabs
        value={tab}
        onValueChange={(value) => setTab(value as IssuePanelTab)}
        className="flex min-h-0 w-full flex-1 flex-col"
      >
        <div className="mb-4 shrink-0">
          <TabsList>
            {ISSUE_PANEL_TABS.map(({ id, label }) => (
              // Six tabs truncate on a phone; the tooltip names them.
              <TabsTrigger key={id} value={id} tooltip={label}>
                {label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <div className="minimal-scrollbar min-h-0 flex-1 overflow-y-auto">
          <TabsContent
            value={ISSUE_PANEL_TAB.EXPLOITABILITY}
            className="flex flex-col gap-4"
          >
            {attributes.attacker_start && attributes.outcome && (
              <div className="grid grid-cols-2 gap-3">
                {/* Inline, not an InfoTooltip: its trigger has no tab stop. */}
                <InfoField label="Starts from">
                  {ATTACKER_START_LABEL[attributes.attacker_start]}
                  <p className="text-text-neutral-tertiary text-xs">
                    Where the attacker has to be standing. Whether they also
                    need a credential is the Access leg.
                  </p>
                </InfoField>
                <InfoField label="Leads to">
                  {ISSUE_OUTCOME_LABEL[attributes.outcome]}
                </InfoField>
              </div>
            )}
            <ul
              aria-label="Exploitability assessment"
              className="divide-border-neutral-secondary flex flex-col divide-y"
            >
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
                      {leg.evidence.length > 0 && (
                        <ul
                          aria-label={`${LEG_LABELS[name]} evidence`}
                          className="mt-1 flex flex-col gap-1"
                        >
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
                    </div>
                    <Badge variant={legBadgeVariant(name, leg.state)}>
                      {LEG_STATE_LABELS[leg.state]}
                    </Badge>
                  </li>
                );
              })}
            </ul>
          </TabsContent>

          <TabsContent value={ISSUE_PANEL_TAB.ATTACK_PATH}>
            <IssueAttackPath
              issue={attributes}
              evidence={evidence}
              onRetry={retry}
              onOpenFinding={openFinding}
            />
          </TabsContent>

          <TabsContent value={ISSUE_PANEL_TAB.FINDINGS}>
            {evidencePending ??
              (evidence.status === "error" || loadedFindings === undefined ? (
                <IssuesLoadError
                  message="Could not load the findings for this issue."
                  onRetry={retry}
                />
              ) : uniqueFindings.length === 0 ? (
                <p className="text-text-neutral-tertiary text-sm">
                  No findings to show for this issue.
                </p>
              ) : (
                <IssueFindings
                  findings={uniqueFindings}
                  total={attributes.findings_count}
                  onOpenFinding={openFinding}
                />
              ))}
          </TabsContent>

          <TabsContent value={ISSUE_PANEL_TAB.RESOURCES}>
            {evidencePending ??
              (evidence.status === "error" ? (
                <IssuesLoadError
                  message="Could not load the resources for this issue."
                  onRetry={retry}
                />
              ) : (
                evidence.status === "loaded" && (
                  <IssueResources
                    resources={evidence.resources}
                    providerId={evidence.providerId}
                  />
                )
              ))}
          </TabsContent>

          {/* Laid out like the finding panel's Remediation tab. */}
          <TabsContent value={ISSUE_PANEL_TAB.REMEDIATION}>
            <div className="flex flex-col gap-1 px-1">
              <span className="text-text-neutral-primary text-sm font-semibold">
                Remediation:
              </span>
              <div className="text-text-neutral-primary text-sm">
                <MarkdownContainer>{attributes.fix}</MarkdownContainer>
              </div>
            </div>
          </TabsContent>

          <TabsContent value={ISSUE_PANEL_TAB.TRIAGE}>
            <IssueTriage
              key={`${issue.id}-${attributes.updated_at}`}
              id={issue.id}
              status={attributes.triage_status}
            />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
};
