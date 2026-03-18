"use client";

import {
  CircleArrowRight,
  CircleChevronLeft,
  CircleChevronRight,
  VolumeOff,
  VolumeX,
} from "lucide-react";
import Image from "next/image";
import { useState } from "react";
import ReactMarkdown from "react-markdown";

import type { ResourceDrawerFinding } from "@/actions/findings";
import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import { getComplianceIcon } from "@/components/icons";
import {
  Badge,
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
import { TreeSpinner } from "@/components/shadcn/tree-view/tree-spinner";
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
import { getRegionFlag } from "@/lib/region-flags";
import { cn } from "@/lib/utils";

import { Muted } from "../../muted";
import { NotificationIndicator } from "../notification-indicator";

interface ResourceDetailDrawerContentProps {
  isLoading: boolean;
  currentIndex: number;
  totalResources: number;
  currentFinding: ResourceDrawerFinding | null;
  otherFindings: ResourceDrawerFinding[];
  onNavigatePrev: () => void;
  onNavigateNext: () => void;
  onMuteComplete: () => void;
}

const MarkdownContainer = ({ children }: { children: string }) => (
  <div className="prose prose-sm dark:prose-invert max-w-none break-words whitespace-normal">
    <ReactMarkdown>{children}</ReactMarkdown>
  </div>
);

function getFailingForLabel(firstSeenAt: string | null): string | null {
  if (!firstSeenAt) return null;

  const start = new Date(firstSeenAt);
  if (isNaN(start.getTime())) return null;

  const now = new Date();
  const diffMs = now.getTime() - start.getTime();
  if (diffMs < 0) return null;

  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays < 1) return "< 1 day";
  if (diffDays < 30) return `${diffDays} day${diffDays > 1 ? "s" : ""}`;

  const diffMonths = Math.floor(diffDays / 30);
  if (diffMonths < 12) return `${diffMonths} month${diffMonths > 1 ? "s" : ""}`;

  const diffYears = Math.floor(diffMonths / 12);
  return `${diffYears} year${diffYears > 1 ? "s" : ""}`;
}

export function ResourceDetailDrawerContent({
  isLoading,
  currentIndex,
  totalResources,
  currentFinding,
  otherFindings,
  onNavigatePrev,
  onNavigateNext,
  onMuteComplete,
}: ResourceDetailDrawerContentProps) {
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);

  if (isLoading) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2 py-16">
        <TreeSpinner className="size-6" />
        <span className="text-text-neutral-tertiary text-sm">
          Loading finding details...
        </span>
      </div>
    );
  }

  if (!currentFinding) {
    return (
      <div className="flex flex-1 items-center justify-center py-16">
        <p className="text-text-neutral-tertiary text-sm">
          No finding data available for this resource.
        </p>
      </div>
    );
  }

  const f = currentFinding;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex < totalResources - 1;

  return (
    <div className="flex h-full min-w-0 flex-col gap-4 overflow-hidden">
      {/* Mute modal — rendered outside drawer content to avoid overlay conflicts */}
      {!f.isMuted && (
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

      {/* Header: status badges + title */}
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <StatusFindingBadge status={f.status as FindingStatus} />
          <SeverityBadge severity={f.severity} />
          {f.delta && (
            <div className="flex items-center gap-1 capitalize">
              <div
                className={cn(
                  "size-2 rounded-full",
                  f.delta === "new"
                    ? "bg-system-severity-high"
                    : "bg-system-severity-low",
                )}
              />
              <span className="text-text-neutral-secondary text-xs">
                {f.delta}
              </span>
            </div>
          )}
          <Muted
            isMuted={f.isMuted}
            mutedReason={f.mutedReason || "This finding is muted"}
          />
        </div>

        <h2 className="text-text-neutral-primary line-clamp-2 text-lg leading-tight font-medium">
          {f.checkTitle}
        </h2>

        {f.complianceFrameworks.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-text-neutral-tertiary text-xs font-medium">
              Compliance Frameworks:
            </span>
            <div className="flex items-center gap-1.5">
              {f.complianceFrameworks.map((framework) => {
                const icon = getComplianceIcon(framework);
                return icon ? (
                  <Image
                    key={framework}
                    src={icon}
                    alt={framework}
                    width={20}
                    height={20}
                    className="shrink-0"
                  />
                ) : (
                  <span
                    key={framework}
                    className="text-text-neutral-secondary text-xs"
                  >
                    {framework}
                  </span>
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
            className="hover:bg-bg-neutral-tertiary disabled:text-text-neutral-tertiary flex size-8 items-center justify-center rounded-md transition-colors disabled:cursor-not-allowed disabled:hover:bg-transparent"
            aria-label="Previous resource"
          >
            <CircleChevronLeft className="size-5" />
          </button>
          <button
            type="button"
            disabled={!hasNext}
            onClick={onNavigateNext}
            className="hover:bg-bg-neutral-tertiary disabled:text-text-neutral-tertiary flex size-8 items-center justify-center rounded-md transition-colors disabled:cursor-not-allowed disabled:hover:bg-transparent"
            aria-label="Next resource"
          >
            <CircleChevronRight className="size-5" />
          </button>
        </div>
      </div>

      {/* Resource card */}
      <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex min-h-0 flex-1 flex-col gap-4 overflow-hidden rounded-lg border p-4">
        {/* Account, Resource, Service, Region, Actions */}
        <div className="flex items-center justify-between">
          <EntityInfo
            cloudProvider={f.providerType}
            entityAlias={f.providerAlias}
            entityId={f.providerUid}
          />
          <EntityInfo
            entityAlias={f.resourceType}
            entityId={f.resourceUid}
            idLabel="UID"
          />
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              Service
            </span>
            <span className="text-text-neutral-primary text-sm">
              {f.resourceService}
            </span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              Region
            </span>
            <span className="text-text-neutral-primary flex items-center gap-1.5 text-sm">
              {getRegionFlag(f.resourceRegion) && (
                <span className="translate-y-px text-base leading-none">
                  {getRegionFlag(f.resourceRegion)}
                </span>
              )}
              {f.resourceRegion}
            </span>
          </div>
          <div>
            <ActionDropdown ariaLabel="Resource actions">
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
            </ActionDropdown>
          </div>
        </div>

        {/* Dates row */}
        <div className="grid grid-cols-3 gap-4">
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              Last detected
            </span>
            <DateWithTime inline dateTime={f.updatedAt || "-"} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              First seen
            </span>
            <DateWithTime inline dateTime={f.firstSeenAt || "-"} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              Failing for
            </span>
            <span className="text-text-neutral-primary text-sm">
              {getFailingForLabel(f.firstSeenAt) || "-"}
            </span>
          </div>
        </div>

        {/* IDs row */}
        <div className="grid grid-cols-3 gap-4">
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              Check ID
            </span>
            <CodeSnippet
              value={f.checkId}
              transparent
              className="max-w-full text-sm"
            />
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              Finding ID
            </span>
            <CodeSnippet
              value={f.id}
              transparent
              className="max-w-full text-sm"
            />
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-[10px]">
              Finding UID
            </span>
            <CodeSnippet
              value={f.uid}
              transparent
              className="max-w-full text-sm"
            />
          </div>
        </div>

        {/* Tabs */}
        <Tabs
          defaultValue="overview"
          className="flex min-h-0 w-full flex-1 flex-col"
        >
          <div className="mb-4 flex items-center justify-between">
            <TabsList>
              <TabsTrigger value="overview">Finding Overview</TabsTrigger>
              <TabsTrigger value="other-findings">
                Other Findings For This Resource
              </TabsTrigger>
            </TabsList>
          </div>

          {/* Finding Overview */}
          <TabsContent
            value="overview"
            className="minimal-scrollbar flex flex-col gap-4 overflow-y-auto"
          >
            {/* Card 1: Risk + Description + Status Extended */}
            {(f.risk || f.description || f.statusExtended) && (
              <Card variant="inner">
                {f.risk && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Risk:
                    </span>
                    <MarkdownContainer>{f.risk}</MarkdownContainer>
                  </div>
                )}
                {f.description && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Description:
                    </span>
                    <MarkdownContainer>{f.description}</MarkdownContainer>
                  </div>
                )}
                {f.statusExtended && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
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
            {(f.remediation.recommendation.text ||
              f.remediation.code.cli ||
              f.remediation.code.terraform ||
              f.remediation.code.nativeiac) && (
              <Card variant="inner">
                {f.remediation.recommendation.text && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Remediation:
                    </span>
                    <div className="flex items-start gap-3">
                      <div className="text-text-neutral-primary flex-1 text-sm">
                        <MarkdownContainer>
                          {f.remediation.recommendation.text}
                        </MarkdownContainer>
                      </div>
                      {f.remediation.recommendation.url && (
                        <CustomLink
                          href={f.remediation.recommendation.url}
                          size="sm"
                          className="shrink-0"
                        >
                          View in Prowler Hub
                        </CustomLink>
                      )}
                    </div>
                  </div>
                )}

                {f.remediation.code.cli && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      CLI Command:
                    </span>
                    <CodeSnippet
                      value={`$ ${f.remediation.code.cli}`}
                      multiline
                      transparent
                      className="max-w-full text-sm"
                    />
                  </div>
                )}

                {f.remediation.code.terraform && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Terraform Command:
                    </span>
                    <CodeSnippet
                      value={`$ ${f.remediation.code.terraform}`}
                      multiline
                      transparent
                      className="max-w-full text-sm"
                    />
                  </div>
                )}

                {f.remediation.code.nativeiac && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      CloudFormation Command:
                    </span>
                    <CodeSnippet
                      value={`$ ${f.remediation.code.nativeiac}`}
                      multiline
                      transparent
                      className="max-w-full text-sm"
                    />
                  </div>
                )}

                {f.remediation.code.other && (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Remediation Steps:
                    </span>
                    <MarkdownContainer>
                      {f.remediation.code.other}
                    </MarkdownContainer>
                  </div>
                )}
              </Card>
            )}

            {f.additionalUrls.length > 0 && (
              <Card variant="inner">
                <div className="flex flex-col gap-1">
                  <span className="text-text-neutral-secondary text-xs">
                    References:
                  </span>
                  <ul className="list-inside list-disc space-y-1">
                    {f.additionalUrls.map((link, idx) => (
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

            {f.categories.length > 0 && (
              <Card variant="inner">
                <div className="flex flex-col gap-1">
                  <span className="text-text-neutral-secondary text-xs">
                    Categories:
                  </span>
                  <p className="text-text-neutral-primary text-sm">
                    {f.categories.join(", ")}
                  </p>
                </div>
              </Card>
            )}
          </TabsContent>

          {/* Other Findings For This Resource */}
          <TabsContent
            value="other-findings"
            className="minimal-scrollbar flex flex-col gap-2 overflow-y-auto"
          >
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
          </TabsContent>
        </Tabs>
      </div>

      {/* Lighthouse AI button */}
      <a
        href="/lighthouse"
        className="flex items-center gap-1.5 rounded-lg px-4 py-3 text-sm font-bold text-slate-950 transition-opacity hover:opacity-90"
        style={{
          background: "linear-gradient(96deg, #2EE59B 3.55%, #62DFF0 98.85%)",
        }}
      >
        <CircleArrowRight className="size-5" />
        View This Finding With Lighthouse AI
      </a>
    </div>
  );
}

function OtherFindingRow({ finding }: { finding: ResourceDrawerFinding }) {
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);

  return (
    <>
      <MuteFindingsModal
        isOpen={isMuteModalOpen}
        onOpenChange={setIsMuteModalOpen}
        findingIds={[finding.id]}
      />
      <TableRow>
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
          </ActionDropdown>
        </TableCell>
      </TableRow>
    </>
  );
}
