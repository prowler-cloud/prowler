import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_SOURCE,
  type LighthouseAttackPathContextItem,
  type LighthouseAttackPathParameter,
  type LighthouseComplianceContextItem,
  type LighthouseFindingContextItem,
  type LighthouseProviderContextItem,
  type LighthouseResourceContextItem,
  type LighthouseScanContextItem,
} from "@/types/lighthouse-context";

import { getLighthouseScopeKey } from "./pages";

const FINDINGS_SCOPE_KEY = getLighthouseScopeKey("/findings");
const RESOURCES_SCOPE_KEY = getLighthouseScopeKey("/resources");
const SCANS_SCOPE_KEY = getLighthouseScopeKey("/scans");
const PROVIDERS_SCOPE_KEY = getLighthouseScopeKey("/providers");

interface FindingGroupContextInput {
  id: string;
  checkId: string;
  checkTitle: string;
  severity: string;
  status: string;
}

interface FindingResourceContextInput {
  findingId: string;
  checkId?: string;
  severity?: string;
  status?: string;
  providerUid?: string;
  resourceUid?: string;
  region?: string;
}

interface ResourceContextInput {
  id: string;
  attributes: {
    uid: string;
    service: string;
    region: string;
    type: string;
    failed_findings_count: number;
  };
  providerUid?: string;
}

interface ComplianceContextInput {
  pathname: string;
  id: string;
  framework: string;
  version?: string;
  scanId?: string;
  providerUid?: string;
  mode?: string;
  section?: string;
  region?: string;
  score?: number;
  passed?: number;
  failed?: number;
  total?: number;
}

interface AttackPathContextInput {
  pathname: string;
  scanId: string;
  queryId?: string | null;
  queryLabel?: string;
  parameters?: Record<string, string | number | boolean>;
  nodeCount?: number;
  edgeCount?: number;
  selectedNode?: { id: string; type?: string } | null;
}

interface ScanContextInput {
  id: string;
  state?: string;
  providerUid?: string;
}

interface ProviderContextInput {
  id: string;
  uid?: string;
  type?: string;
}

export function buildFindingSummaryContext(
  total: number,
): LighthouseFindingContextItem {
  const safeTotal = toSafeCount(total);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.FINDING,
    id: "summary",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: FINDINGS_SCOPE_KEY,
    label: `${safeTotal} findings`,
    findingId: "summary",
    total: safeTotal,
  };
}

export function buildFindingGroupContext(
  group: FindingGroupContextInput,
): LighthouseFindingContextItem {
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.FINDING,
    id: toBoundedString(group.id),
    source: LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
    scopeKey: FINDINGS_SCOPE_KEY,
    label: toBoundedString(group.checkTitle),
    findingId: toBoundedString(group.id),
    checkId: toBoundedString(group.checkId),
    severity: toBoundedString(group.severity),
    status: toBoundedString(group.status),
  };
}

export function buildFindingResourceContext(
  finding: FindingResourceContextInput,
): LighthouseFindingContextItem {
  const safeFindingId = toBoundedString(finding.findingId);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.FINDING,
    id: safeFindingId,
    source: LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
    scopeKey: FINDINGS_SCOPE_KEY,
    label: "Selected finding",
    findingId: safeFindingId,
    checkId: optionalBoundedString(finding.checkId),
    severity: optionalBoundedString(finding.severity),
    status: optionalBoundedString(finding.status),
    providerUid: optionalBoundedString(finding.providerUid),
    resourceUid: optionalBoundedString(finding.resourceUid),
    region: optionalBoundedString(finding.region),
  };
}

export function buildResourceSummaryContext(
  total: number,
): LighthouseResourceContextItem {
  const safeTotal = toSafeCount(total);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.RESOURCE,
    id: "summary",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: RESOURCES_SCOPE_KEY,
    label: `${safeTotal} resources`,
    resourceId: "summary",
    total: safeTotal,
  };
}

export function buildResourceContext(
  resource: ResourceContextInput,
): LighthouseResourceContextItem {
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.RESOURCE,
    id: toBoundedString(resource.id),
    source: LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
    scopeKey: RESOURCES_SCOPE_KEY,
    label: "Selected resource",
    resourceId: toBoundedString(resource.id),
    resourceUid: toBoundedString(resource.attributes.uid),
    providerUid: optionalBoundedString(resource.providerUid),
    service: toBoundedString(resource.attributes.service),
    region: toBoundedString(resource.attributes.region),
    resourceType: toBoundedString(resource.attributes.type),
    failedFindingsCount: toSafeCount(resource.attributes.failed_findings_count),
  };
}

export function buildComplianceContext(
  input: ComplianceContextInput,
): LighthouseComplianceContextItem {
  const total = optionalSafeCount(input.total);
  const passed = optionalSafeCount(input.passed);
  const failed = optionalSafeCount(input.failed);
  const score =
    input.score !== undefined
      ? toSafeScore(input.score)
      : total && passed !== undefined
        ? toSafeScore((passed / total) * 100)
        : undefined;
  const hasTotals =
    passed !== undefined || failed !== undefined || total !== undefined;

  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.COMPLIANCE,
    id: toBoundedString(input.id),
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: toBoundedString(input.framework),
    framework: toBoundedString(input.framework),
    version: optionalBoundedString(input.version),
    scanId: optionalBoundedString(input.scanId),
    providerUid: optionalBoundedString(input.providerUid),
    mode: optionalBoundedString(input.mode),
    section: optionalBoundedString(input.section),
    region: optionalBoundedString(input.region),
    score,
    totals: hasTotals ? { passed, failed, total } : undefined,
  };
}

export function buildAttackPathContext(
  input: AttackPathContextInput,
): LighthouseAttackPathContextItem {
  const parameters = sanitizeAttackPathParameters(input.parameters);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.ATTACK_PATH,
    id: input.queryId ? "current-query" : "current-scan",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: toBoundedString(input.queryLabel || "Selected attack-path scan"),
    scanId: toBoundedString(input.scanId),
    queryId: optionalBoundedString(input.queryId ?? undefined),
    parameters: Object.keys(parameters).length > 0 ? parameters : undefined,
    nodeCount: optionalSafeCount(input.nodeCount),
    edgeCount: optionalSafeCount(input.edgeCount),
    selectedNodeId: optionalBoundedString(input.selectedNode?.id),
    selectedNodeType: optionalBoundedString(input.selectedNode?.type),
  };
}

export function buildScanSummaryContext(
  total: number,
  state: string,
): LighthouseScanContextItem {
  const safeTotal = toSafeCount(total);
  const safeState = toBoundedString(state);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.SCAN,
    id: "summary",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: SCANS_SCOPE_KEY,
    label: `${safeTotal} ${safeState} scans`,
    state: safeState,
    total: safeTotal,
  };
}

export function buildScanContext(
  input: ScanContextInput,
): LighthouseScanContextItem {
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.SCAN,
    id: toBoundedString(input.id),
    source: LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
    scopeKey: SCANS_SCOPE_KEY,
    label: "Selected scan",
    scanId: toBoundedString(input.id),
    state: optionalBoundedString(input.state),
    providerUid: optionalBoundedString(input.providerUid),
  };
}

export function buildProviderSummaryContext(
  total: number,
): LighthouseProviderContextItem {
  const safeTotal = toSafeCount(total);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.PROVIDER,
    id: "summary",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: PROVIDERS_SCOPE_KEY,
    label: `${safeTotal} providers`,
    total: safeTotal,
  };
}

export function buildProviderContext(
  input: ProviderContextInput,
): LighthouseProviderContextItem {
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.PROVIDER,
    id: toBoundedString(input.id),
    source: LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
    scopeKey: PROVIDERS_SCOPE_KEY,
    label: "Selected provider",
    providerId: toBoundedString(input.id),
    providerUid: optionalBoundedString(input.uid),
    providerType: optionalBoundedString(input.type),
  };
}

function toBoundedString(value: string): string {
  return value.slice(0, 256);
}

function optionalBoundedString(value: string | undefined): string | undefined {
  return value ? toBoundedString(value) : undefined;
}

function toSafeCount(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
}

function optionalSafeCount(value: number | undefined): number | undefined {
  return value === undefined ? undefined : toSafeCount(value);
}

function toSafeScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(100, Math.max(0, Math.round(value * 100) / 100));
}

function sanitizeAttackPathParameters(
  parameters: AttackPathContextInput["parameters"],
): Record<string, LighthouseAttackPathParameter> {
  if (!parameters) return {};

  return Object.fromEntries(
    Object.entries(parameters)
      .filter(
        ([key, value]) =>
          !/password|secret|token|credential|query/i.test(key) && value !== "",
      )
      .slice(0, 8)
      .map(([key, value]) => [
        toBoundedString(key),
        typeof value === "string" ? toBoundedString(value) : value,
      ]),
  );
}
