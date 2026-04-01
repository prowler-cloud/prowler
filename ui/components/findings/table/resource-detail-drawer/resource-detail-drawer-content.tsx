"use client";

import {
  Box,
  CircleArrowRight,
  CircleChevronLeft,
  CircleChevronRight,
  Container,
  ExternalLink,
  VolumeOff,
  VolumeX,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import type { ResourceDrawerFinding } from "@/actions/findings";
import { MarkdownContainer } from "@/components/findings/markdown-container";
import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { getComplianceIcon } from "@/components/icons";
import { JiraIcon } from "@/components/icons/services/IconServices";
import {
  Badge,
  Button,
  InfoField,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn";
import { Card } from "@/components/shadcn/card/card";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { EventsTimeline } from "@/components/shared/events-timeline/events-timeline";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/table/severity-badge";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/ui/table/status-finding-badge";
import { getFailingForLabel } from "@/lib/date-utils";
import { formatDuration } from "@/lib/date-utils";
import { getRegionFlag } from "@/lib/region-flags";
import type { ComplianceOverviewData } from "@/types/compliance";

import { Muted } from "../../muted";
import { DeltaIndicator } from "../delta-indicator";
import { NotificationIndicator } from "../notification-indicator";
import { ResourceDetailSkeleton } from "./resource-detail-skeleton";
import type { CheckMeta } from "./use-resource-detail-drawer";

/** Strip markdown code fences (```lang ... ```) so CodeSnippet shows clean code. */
function stripCodeFences(code: string): string {
  return code
    .replace(/^```\w*\n?/, "")
    .replace(/\n?```\s*$/, "")
    .trim();
}

function normalizeComplianceFrameworkName(framework: string): string {
  return framework
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-");
}

function parseSelectedScanIds(scanFilterValue: string | null): string[] {
  if (!scanFilterValue) {
    return [];
  }

  return scanFilterValue
    .split(",")
    .map((scanId) => scanId.trim())
    .filter(Boolean);
}

function resolveComplianceMatch(
  compliances: ComplianceOverviewData[] | undefined,
  framework: string,
): {
  complianceId: string;
  framework: string;
  version: string;
} | null {
  if (!compliances?.length) {
    return null;
  }

  const normalizedFramework = normalizeComplianceFrameworkName(framework);
  const match = compliances.find(
    (compliance) =>
      normalizeComplianceFrameworkName(compliance.attributes.framework) ===
      normalizedFramework,
  );

  if (!match) {
    return null;
  }

  return {
    complianceId: match.id,
    framework: match.attributes.framework,
    version: match.attributes.version,
  };
}

function buildComplianceDetailHref({
  complianceId,
  framework,
  version,
  scanId,
  regionFilter,
  currentFinding,
  includeScanData,
}: {
  complianceId: string;
  framework: string;
  version: string;
  scanId: string;
  regionFilter: string | null;
  currentFinding: ResourceDrawerFinding | null;
  includeScanData: boolean;
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

  if (includeScanData && currentFinding?.scan?.completedAt) {
    params.set(
      "scanData",
      JSON.stringify({
        id: currentFinding.scan.id,
        providerInfo: {
          provider: currentFinding.providerType,
          alias: currentFinding.providerAlias,
          uid: currentFinding.providerUid,
        },
        attributes: {
          name: currentFinding.scan.name,
          completed_at: currentFinding.scan.completedAt,
        },
      }),
    );
  }

  return `/compliance/${encodeURIComponent(framework)}?${params.toString()}`;
}

interface ResourceDetailDrawerContentProps {
  isLoading: boolean;
  isNavigating: boolean;
  checkMeta: CheckMeta | null;
  currentIndex: number;
  totalResources: number;
  currentFinding: ResourceDrawerFinding | null;
  otherFindings: ResourceDrawerFinding[];
  onNavigatePrev: () => void;
  onNavigateNext: () => void;
  onMuteComplete: () => void;
}

export function ResourceDetailDrawerContent({
  isLoading,
  isNavigating,
  checkMeta,
  currentIndex,
  totalResources,
  currentFinding,
  otherFindings,
  onNavigatePrev,
  onNavigateNext,
  onMuteComplete,
}: ResourceDetailDrawerContentProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);
  const [isJiraModalOpen, setIsJiraModalOpen] = useState(false);
  const [resolvingFramework, setResolvingFramework] = useState<string | null>(
    null,
  );

  // Initial load — no check metadata yet
  if (!checkMeta && isLoading) {
    return (
      <div className="flex h-full min-w-0 flex-col gap-4 overflow-hidden">
        {/* Header skeleton */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-3">
            <Skeleton className="h-6 w-14 rounded-md" />
            <Skeleton className="h-6 w-16 rounded-md" />
          </div>
          <Skeleton className="h-6 w-3/4 rounded" />
        </div>
        {/* Navigation skeleton */}
        <div className="flex items-center justify-between">
          <Skeleton className="h-7 w-48 rounded" />
          <div className="flex gap-1">
            <Skeleton className="size-8 rounded-md" />
            <Skeleton className="size-8 rounded-md" />
          </div>
        </div>
        {/* Resource card skeleton */}
        <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex min-h-0 flex-1 flex-col gap-4 rounded-lg border p-4">
          <ResourceDetailSkeleton />
        </div>
      </div>
    );
  }

  if (!checkMeta) {
    return (
      <div className="flex flex-1 items-center justify-center py-16">
        <p className="text-text-neutral-tertiary text-sm">
          No finding data available for this resource.
        </p>
      </div>
    );
  }

  // checkMeta is always available from here.
  // currentFinding may be null during resource loading (e.g. drawer reopen).
  const f = currentFinding;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex < totalResources - 1;
  const selectedScanIds = parseSelectedScanIds(
    searchParams.get("filter[scan__in]"),
  );
  const complianceScanId =
    selectedScanIds.length === 1
      ? selectedScanIds[0]
      : selectedScanIds.length === 0
        ? (f?.scan?.id ?? null)
        : null;
  const regionFilter = searchParams.get("filter[region__in]");

  const handleOpenCompliance = async (framework: string) => {
    if (!complianceScanId || resolvingFramework) {
      return;
    }

    setResolvingFramework(framework);

    try {
      const compliancesOverview = await getCompliancesOverview({
        scanId: complianceScanId,
      });
      const complianceMatch = resolveComplianceMatch(
        compliancesOverview?.data,
        framework,
      );

      if (!complianceMatch) {
        return;
      }

      router.push(
        buildComplianceDetailHref({
          complianceId: complianceMatch.complianceId,
          framework: complianceMatch.framework,
          version: complianceMatch.version,
          scanId: complianceScanId,
          regionFilter,
          currentFinding: f,
          includeScanData: f?.scan?.id === complianceScanId,
        }),
      );
    } catch (error) {
      console.error("Error resolving compliance detail:", error);
    } finally {
      setResolvingFramework(null);
    }
  };

  return (
    <div className="flex h-full min-w-0 flex-col gap-4 overflow-hidden">
      {/* Mute modal — rendered outside drawer content to avoid overlay conflicts */}
      {f && !f.isMuted && (
        <MuteFindingsModal
          isOpen={isMuteModalOpen}
          onOpenChange={setIsMuteModalOpen}
          findingIds={[f.id]}
          onComplete={() => {
            setIsMuteModalOpen(false);
            onMuteComplete();
          }}
        />
      )}
      {f && (
        <SendToJiraModal
          isOpen={isJiraModalOpen}
          onOpenChange={setIsJiraModalOpen}
          findingId={f.id}
          findingTitle={checkMeta.checkTitle}
        />
      )}

      {/* Header: status badges + title (check-level from checkMeta) */}
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-3">
          {f && <StatusFindingBadge status={f.status as FindingStatus} />}
          {f && <SeverityBadge severity={f.severity} />}
          {f?.delta && (
            <div className="flex items-center gap-1 capitalize">
              <DeltaIndicator delta={f.delta} />
              <span className="text-text-neutral-secondary text-xs">
                {f.delta}
              </span>
            </div>
          )}
          {f && (
            <Muted
              isMuted={f.isMuted}
              mutedReason={f.mutedReason || "This finding is muted"}
            />
          )}
        </div>

        <h2 className="text-text-neutral-primary line-clamp-2 text-lg leading-tight font-medium">
          {checkMeta.checkTitle}
        </h2>

        {checkMeta.complianceFrameworks.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <span className="text-text-neutral-tertiary text-xs font-medium">
              Compliance Frameworks:
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {checkMeta.complianceFrameworks.map((framework) => {
                const icon = getComplianceIcon(framework);
                const isNavigable = Boolean(complianceScanId);
                const isResolving = resolvingFramework === framework;

                return icon ? (
                  <Tooltip key={framework}>
                    <TooltipTrigger asChild>
                      {isNavigable ? (
                        <button
                          type="button"
                          aria-label={`Open ${framework} compliance details`}
                          onClick={() => void handleOpenCompliance(framework)}
                          disabled={Boolean(resolvingFramework)}
                          className="flex size-7 shrink-0 items-center justify-center rounded-md border border-gray-300 bg-white p-0.5 transition-shadow hover:shadow-sm focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-wait disabled:opacity-70"
                        >
                          <Image
                            src={icon}
                            alt={framework}
                            width={20}
                            height={20}
                            className="size-5 object-contain"
                          />
                          {isResolving && (
                            <span className="sr-only">Opening compliance</span>
                          )}
                        </button>
                      ) : (
                        <div className="flex size-7 shrink-0 items-center justify-center rounded-md border border-gray-300 bg-white p-0.5">
                          <Image
                            src={icon}
                            alt={framework}
                            width={20}
                            height={20}
                            className="size-5 object-contain"
                          />
                        </div>
                      )}
                    </TooltipTrigger>
                    <TooltipContent>{framework}</TooltipContent>
                  </Tooltip>
                ) : (
                  <Tooltip key={framework}>
                    <TooltipTrigger asChild>
                      {isNavigable ? (
                        <button
                          type="button"
                          aria-label={`Open ${framework} compliance details`}
                          onClick={() => void handleOpenCompliance(framework)}
                          disabled={Boolean(resolvingFramework)}
                          className="text-text-neutral-secondary inline-flex h-7 shrink-0 items-center rounded-md border border-gray-300 bg-white px-1.5 text-xs transition-shadow hover:shadow-sm focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-wait disabled:opacity-70"
                        >
                          {framework}
                          {isResolving && (
                            <span className="sr-only">Opening compliance</span>
                          )}
                        </button>
                      ) : (
                        <span className="text-text-neutral-secondary inline-flex h-7 shrink-0 items-center rounded-md border border-gray-300 bg-white px-1.5 text-xs">
                          {framework}
                        </span>
                      )}
                    </TooltipTrigger>
                    <TooltipContent>{framework}</TooltipContent>
                  </Tooltip>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Navigation: "Impacted Resource (X of N)" */}
      <div className="flex items-center justify-between">
        <Badge variant="tag" className="rounded text-sm">
          Impacted Resource
          <span className="font-bold">{currentIndex + 1}</span>
          <span className="font-normal">of</span>
          <span className="font-bold">{totalResources}</span>
        </Badge>
        <div className="flex items-center gap-0">
          <button
            type="button"
            disabled={!hasPrev}
            onClick={onNavigatePrev}
            className="text-text-neutral-secondary hover:bg-bg-neutral-tertiary disabled:text-text-neutral-tertiary flex size-8 items-center justify-center rounded-md transition-colors disabled:cursor-not-allowed disabled:hover:bg-transparent"
            aria-label="Previous resource"
          >
            <CircleChevronLeft className="size-5" />
          </button>
          <button
            type="button"
            disabled={!hasNext}
            onClick={onNavigateNext}
            className="text-text-neutral-secondary hover:bg-bg-neutral-tertiary disabled:text-text-neutral-tertiary flex size-8 items-center justify-center rounded-md transition-colors disabled:cursor-not-allowed disabled:hover:bg-transparent"
            aria-label="Next resource"
          >
            <CircleChevronRight className="size-5" />
          </button>
        </div>
      </div>

      {/* Resource card */}
      <div className="border-border-neutral-secondary bg-bg-neutral-secondary minimal-scrollbar flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto rounded-lg border p-4">
        {/* Resource info — shows loading when currentFinding is not yet available */}
        {!f || isNavigating ? (
          <ResourceDetailSkeleton />
        ) : (
          <>
            <div className="flex items-start gap-4">
              {/* Resource info grid — 4 data columns */}
              <div className="grid min-w-0 flex-1 grid-cols-1 gap-4 md:grid-cols-4 md:gap-x-8 md:gap-y-4">
                {/* Row 1: Account, Resource, Service, Region */}
                <EntityInfo
                  cloudProvider={f.providerType}
                  nameIcon={<Box className="size-4" />}
                  entityAlias={f.providerAlias}
                  entityId={f.providerUid}
                />
                <EntityInfo
                  nameIcon={<Container className="size-4" />}
                  entityAlias={f.resourceGroup}
                  entityId={f.resourceUid}
                  idLabel="UID"
                />
                <InfoField label="Service" variant="compact">
                  {f.resourceService}
                </InfoField>
                <InfoField label="Region" variant="compact">
                  <span className="flex items-center gap-1.5">
                    {getRegionFlag(f.resourceRegion) && (
                      <span className="translate-y-px text-base leading-none">
                        {getRegionFlag(f.resourceRegion)}
                      </span>
                    )}
                    {f.resourceRegion}
                  </span>
                </InfoField>

                {/* Row 2: Dates */}
                <InfoField label="Last detected" variant="compact">
                  <DateWithTime inline dateTime={f.updatedAt || "-"} />
                </InfoField>
                <InfoField label="First seen" variant="compact">
                  <DateWithTime inline dateTime={f.firstSeenAt || "-"} />
                </InfoField>
                <InfoField label="Failing for" variant="compact">
                  {getFailingForLabel(f.firstSeenAt) || "-"}
                </InfoField>
                <div className="hidden md:block" />

                {/* Row 3: IDs */}
                <InfoField label="Check ID" variant="compact">
                  <CodeSnippet
                    value={checkMeta.checkId}
                    transparent
                    className="max-w-full text-sm"
                  />
                </InfoField>
                <InfoField label="Finding ID" variant="compact">
                  <CodeSnippet
                    value={f.id}
                    transparent
                    className="max-w-full text-sm"
                  />
                </InfoField>
                <InfoField label="Finding UID" variant="compact">
                  <CodeSnippet
                    value={f.uid}
                    transparent
                    className="max-w-full text-sm"
                  />
                </InfoField>
              </div>

              {/* Actions button — fixed size, aligned with row 1 */}
              <div className="shrink-0">
                <ActionDropdown variant="bordered" ariaLabel="Resource actions">
                  <ActionDropdownItem
                    icon={
                      f.isMuted ? (
                        <VolumeOff className="size-5" />
                      ) : (
                        <VolumeX className="size-5" />
                      )
                    }
                    label={f.isMuted ? "Muted" : "Mute"}
                    disabled={f.isMuted}
                    onSelect={() => setIsMuteModalOpen(true)}
                  />
                  <ActionDropdownItem
                    icon={<JiraIcon size={20} />}
                    label="Send to Jira"
                    onSelect={() => setIsJiraModalOpen(true)}
                  />
                </ActionDropdown>
              </div>
            </div>
          </>
        )}

        {/* Tabs */}
        <Tabs
          defaultValue="overview"
          className="mt-2 flex min-h-fit w-full flex-1 flex-col md:min-h-0"
        >
          <div className="mb-4 flex items-center justify-between">
            <TabsList>
              <TabsTrigger value="overview">Finding Overview</TabsTrigger>
              <TabsTrigger value="other-findings">
                Other Findings For This Resource
              </TabsTrigger>
              <TabsTrigger value="scans">Scans</TabsTrigger>
              <TabsTrigger value="events">Events</TabsTrigger>
            </TabsList>
          </div>

          {/* Finding Overview — check-level data from checkMeta (always stable) */}
          <TabsContent
            value="overview"
            className="minimal-scrollbar flex flex-col gap-4 overflow-y-auto"
          >
            {/* Card 1: Risk + Description + Status Extended */}
            {(checkMeta.risk || checkMeta.description || f?.statusExtended) && (
              <Card variant="inner">
                {checkMeta.risk && (
                  <Card variant="danger">
                    <span className="text-text-neutral-secondary text-sm font-semibold">
                      Risk:
                    </span>
                    <MarkdownContainer>{checkMeta.risk}</MarkdownContainer>
                  </Card>
                )}
                {checkMeta.description && (
                  <div className="border-default-200 flex flex-col gap-1 border-b pb-4">
                    <span className="text-text-neutral-secondary text-sm font-semibold">
                      Description:
                    </span>
                    <MarkdownContainer>
                      {checkMeta.description}
                    </MarkdownContainer>
                  </div>
                )}
                {f?.statusExtended && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-sm font-semibold">
                      Status Extended:
                    </span>
                    <p className="text-text-neutral-primary text-sm">
                      {f.statusExtended}
                    </p>
                  </div>
                )}
              </Card>
            )}

            {/* Card 2: Remediation + Commands */}
            {(checkMeta.remediation.recommendation.text ||
              checkMeta.remediation.code.cli ||
              checkMeta.remediation.code.terraform ||
              checkMeta.remediation.code.nativeiac) && (
              <Card variant="inner">
                {checkMeta.remediation.recommendation.text && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Remediation:
                    </span>
                    <div className="flex items-start gap-3">
                      <div className="text-text-neutral-primary flex-1 text-sm">
                        <MarkdownContainer>
                          {checkMeta.remediation.recommendation.text}
                        </MarkdownContainer>
                      </div>
                      {checkMeta.remediation.recommendation.url && (
                        <CustomLink
                          href={checkMeta.remediation.recommendation.url}
                          size="sm"
                          className="shrink-0"
                        >
                          View in Prowler Hub
                        </CustomLink>
                      )}
                    </div>
                  </div>
                )}

                {checkMeta.remediation.code.cli && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      CLI Command:
                    </span>
                    <CodeSnippet
                      value={`$ ${stripCodeFences(checkMeta.remediation.code.cli)}`}
                      multiline
                      transparent
                      className="max-w-full text-sm"
                    />
                  </div>
                )}

                {checkMeta.remediation.code.terraform && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Terraform:
                    </span>
                    <CodeSnippet
                      value={stripCodeFences(
                        checkMeta.remediation.code.terraform,
                      )}
                      multiline
                      transparent
                      className="max-w-full text-sm"
                    />
                  </div>
                )}

                {checkMeta.remediation.code.nativeiac && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      CloudFormation:
                    </span>
                    <CodeSnippet
                      value={stripCodeFences(
                        checkMeta.remediation.code.nativeiac,
                      )}
                      multiline
                      transparent
                      className="max-w-full text-sm"
                    />
                  </div>
                )}

                {checkMeta.remediation.code.other && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Remediation Steps:
                    </span>
                    <MarkdownContainer>
                      {checkMeta.remediation.code.other}
                    </MarkdownContainer>
                  </div>
                )}
              </Card>
            )}

            {checkMeta.additionalUrls.length > 0 && (
              <Card variant="inner">
                <div className="flex flex-col gap-1">
                  <span className="text-text-neutral-secondary text-xs">
                    References:
                  </span>
                  <ul className="list-inside list-disc space-y-1">
                    {checkMeta.additionalUrls.map((link, idx) => (
                      <li key={idx}>
                        <CustomLink
                          href={link}
                          size="sm"
                          className="break-all whitespace-normal!"
                        >
                          {link}
                        </CustomLink>
                      </li>
                    ))}
                  </ul>
                </div>
              </Card>
            )}

            {checkMeta.categories.length > 0 && (
              <Card variant="inner">
                <div className="flex flex-col gap-1">
                  <span className="text-text-neutral-secondary text-xs">
                    Categories:
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    {checkMeta.categories.map((category) => (
                      <Badge
                        key={category}
                        variant="outline"
                        className="text-xs capitalize"
                      >
                        {category}
                      </Badge>
                    ))}
                  </div>
                </div>
              </Card>
            )}
          </TabsContent>

          {/* Other Findings For This Resource */}
          <TabsContent
            value="other-findings"
            className="minimal-scrollbar flex flex-col gap-2 overflow-y-auto"
          >
            {!f || isNavigating ? (
              <div className="flex items-center justify-center py-8">
                <Spinner className="size-5" />
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <h4 className="text-text-neutral-primary text-sm font-medium">
                    Failed Findings For This Resource
                  </h4>
                  <span className="text-text-neutral-tertiary text-sm">
                    {otherFindings.length} Total Entries
                  </span>
                </div>

                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10" />
                      <TableHead>
                        <span className="text-text-neutral-secondary text-sm font-medium">
                          Status
                        </span>
                      </TableHead>
                      <TableHead>
                        <span className="text-text-neutral-secondary text-sm font-medium">
                          Finding
                        </span>
                      </TableHead>
                      <TableHead>
                        <span className="text-text-neutral-secondary text-sm font-medium">
                          Severity
                        </span>
                      </TableHead>
                      <TableHead>
                        <span className="text-text-neutral-secondary text-sm font-medium">
                          Time
                        </span>
                      </TableHead>
                      <TableHead className="w-10" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {otherFindings.length > 0 ? (
                      otherFindings.map((finding) => (
                        <OtherFindingRow key={finding.id} finding={finding} />
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={6} className="h-16 text-center">
                          <span className="text-text-neutral-tertiary text-sm">
                            No other findings for this resource.
                          </span>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </>
            )}
          </TabsContent>

          {/* Scans Tab */}
          <TabsContent value="scans" className="flex flex-col gap-4">
            {f?.scan ? (
              <>
                <div className="flex items-center justify-between">
                  <p className="text-text-neutral-secondary text-xs">
                    Showing the latest scan that evaluated this finding
                  </p>
                  <Button variant="link" size="link-sm" asChild>
                    <Link
                      href={`/scans?id=${f.scan.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      View scan
                      <ExternalLink className="size-3" />
                    </Link>
                  </Button>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <InfoField label="Scan Name" variant="compact">
                    {f.scan.name || "N/A"}
                  </InfoField>
                  <InfoField label="Resources Scanned" variant="compact">
                    {f.scan.uniqueResourceCount}
                  </InfoField>
                  <InfoField label="Progress" variant="compact">
                    {f.scan.progress}%
                  </InfoField>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <InfoField label="Trigger" variant="compact">
                    {f.scan.trigger}
                  </InfoField>
                  <InfoField label="State" variant="compact">
                    {f.scan.state}
                  </InfoField>
                  <InfoField label="Duration" variant="compact">
                    {formatDuration(f.scan.duration)}
                  </InfoField>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <InfoField label="Started At" variant="compact">
                    <DateWithTime inline dateTime={f.scan.startedAt || "-"} />
                  </InfoField>
                  <InfoField label="Completed At" variant="compact">
                    <DateWithTime inline dateTime={f.scan.completedAt || "-"} />
                  </InfoField>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <InfoField label="Launched At" variant="compact">
                    <DateWithTime inline dateTime={f.scan.insertedAt || "-"} />
                  </InfoField>
                  {f.scan.scheduledAt && (
                    <InfoField label="Scheduled At" variant="compact">
                      <DateWithTime inline dateTime={f.scan.scheduledAt} />
                    </InfoField>
                  )}
                </div>
              </>
            ) : (
              <p className="text-text-neutral-tertiary text-sm">
                Scan information is not available.
              </p>
            )}
          </TabsContent>

          {/* Events Tab */}
          <TabsContent
            value="events"
            className="flex min-h-0 flex-1 flex-col gap-4"
          >
            <EventsTimeline
              resourceId={f?.resourceId}
              isAwsProvider={f?.providerType === "aws"}
            />
          </TabsContent>
        </Tabs>
      </div>

      {/* Lighthouse AI button */}
      <a
        href={`/lighthouse?${new URLSearchParams({ prompt: `Analyze this security finding and provide remediation guidance:\n\n- **Finding**: ${checkMeta.checkTitle}\n- **Check ID**: ${checkMeta.checkId}\n- **Severity**: ${f?.severity ?? "unknown"}\n- **Status**: ${f?.status ?? "unknown"}${f?.statusExtended ? `\n- **Detail**: ${f.statusExtended}` : ""}${checkMeta.risk ? `\n- **Risk**: ${checkMeta.risk}` : ""}` }).toString()}`}
        className="flex items-center gap-1.5 rounded-lg px-4 py-3 text-sm font-bold text-slate-900 transition-opacity hover:opacity-90"
        style={{
          background: "var(--gradient-lighthouse)",
        }}
      >
        <CircleArrowRight className="size-5" />
        Analyze This Finding With Lighthouse AI
      </a>
    </div>
  );
}

function OtherFindingRow({ finding }: { finding: ResourceDrawerFinding }) {
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);
  const [isJiraModalOpen, setIsJiraModalOpen] = useState(false);

  const findingUrl = `/findings?filter%5Bcheck_id__in%5D=${encodeURIComponent(finding.checkId)}&filter%5Bmuted%5D=include`;

  return (
    <>
      {!finding.isMuted && (
        <MuteFindingsModal
          isOpen={isMuteModalOpen}
          onOpenChange={setIsMuteModalOpen}
          findingIds={[finding.id]}
        />
      )}
      <SendToJiraModal
        isOpen={isJiraModalOpen}
        onOpenChange={setIsJiraModalOpen}
        findingId={finding.id}
        findingTitle={finding.checkTitle}
      />
      <TableRow
        className="cursor-pointer"
        onClick={() => window.open(findingUrl, "_blank", "noopener,noreferrer")}
      >
        <TableCell className="w-10">
          <NotificationIndicator isMuted={finding.isMuted} />
        </TableCell>
        <TableCell>
          <StatusFindingBadge status={finding.status as FindingStatus} />
        </TableCell>
        <TableCell>
          <p className="text-text-neutral-primary max-w-[300px] truncate text-sm">
            {finding.checkTitle}
          </p>
        </TableCell>
        <TableCell>
          <SeverityBadge severity={finding.severity} />
        </TableCell>
        <TableCell>
          <DateWithTime dateTime={finding.updatedAt} />
        </TableCell>
        <TableCell className="w-10">
          <div onClick={(e) => e.stopPropagation()}>
            <ActionDropdown ariaLabel="Finding actions">
              <ActionDropdownItem
                icon={
                  finding.isMuted ? (
                    <VolumeOff className="size-5" />
                  ) : (
                    <VolumeX className="size-5" />
                  )
                }
                label={finding.isMuted ? "Muted" : "Mute"}
                disabled={finding.isMuted}
                onSelect={() => setIsMuteModalOpen(true)}
              />
              <ActionDropdownItem
                icon={<JiraIcon size={20} />}
                label="Send to Jira"
                onSelect={() => setIsJiraModalOpen(true)}
              />
            </ActionDropdown>
          </div>
        </TableCell>
      </TableRow>
    </>
  );
}
