import {
  ATTACK_PATH_QUERY_KIND,
  type AttackPathGraphData,
  type AttackPathQueryKind,
  type GraphEdge,
} from "@/types/attack-paths";
import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_LIMIT,
  LIGHTHOUSE_CONTEXT_SOURCE,
  type LighthouseAlertContextItem,
  type LighthouseAttackPathContextItem,
  type LighthouseAttackPathParameter,
  type LighthouseComplianceContextItem,
  type LighthouseFindingContextItem,
  type LighthouseProviderContextItem,
  type LighthouseResourceContextItem,
  type LighthouseScanContextItem,
} from "@/types/lighthouse-context";

import type { LighthouseComplianceContextMode } from "./constants";
import {
  containsSensitiveLighthouseContextValue,
  getLighthouseScopeKey,
} from "./pages";

const ALERTS_SCOPE_KEY = getLighthouseScopeKey("/alerts");
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

interface FocusedAlertContextInput {
  id: string;
  name?: string;
  trigger?: string;
  enabled?: boolean;
}

interface FindingStatusSummaryContextInput {
  pathname: string;
  passed: number;
  failed: number;
  newPassed?: number;
  newFailed?: number;
}

interface FindingSeveritySummaryContextInput {
  pathname: string;
  severityCounts: Record<string, number>;
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

interface FocusedFindingContextInput extends FindingResourceContextInput {
  pathname: string;
}

interface ResourceContextAttributes {
  uid: string;
  service: string;
  region: string;
  type: string;
  failed_findings_count: number;
}

interface ResourceContextInput {
  id: string;
  attributes: ResourceContextAttributes;
  providerUid?: string;
}

interface FocusedResourceContextInput extends ResourceContextInput {
  pathname: string;
}

interface ComplianceContextInput {
  pathname: string;
  id: string;
  framework: string;
  version?: string;
  scanId?: string;
  providerUid?: string;
  mode?: LighthouseComplianceContextMode;
  section?: string;
  region?: string;
  score?: number;
  scoreDelta?: number;
  criticalRequirementsCount?: number;
  worstSection?: string;
  worstSectionScore?: number;
  passed?: number;
  failed?: number;
  total?: number;
}

interface AttackPathSelectedNodeInput {
  id: string;
  type?: string;
}

interface AttackPathContextInput {
  pathname: string;
  scanId: string;
  queryId?: string | null;
  queryLabel?: string;
  queryKind?: AttackPathQueryKind;
  parameters?: Record<string, string | number | boolean>;
  graphData?: AttackPathGraphData | null;
  nodeCount?: number;
  edgeCount?: number;
  selectedNode?: AttackPathSelectedNodeInput | null;
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

interface FilteredProviderContextInput {
  pathname: string;
  id: string;
  uid?: string;
  type?: string;
  alias?: string;
}

interface ProviderGroupContextInput {
  pathname: string;
  id: string;
  name: string;
}

interface ServiceSummaryContextInput {
  pathname: string;
  service: string;
  failedFindingsCount: number;
  total?: number;
}

export function buildAlertSummaryContext(
  total: number,
  enabledCount?: number,
): LighthouseAlertContextItem {
  const safeTotal = toSafeCount(total);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.ALERT,
    id: "summary",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: ALERTS_SCOPE_KEY,
    label: `${safeTotal} alert rules`,
    total: safeTotal,
    enabledCount: optionalSafeCount(enabledCount),
  };
}

export function buildFocusedAlertContext(
  input: FocusedAlertContextInput,
): LighthouseAlertContextItem {
  const safeId = toBoundedString(input.id);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.ALERT,
    id: safeId,
    source: LIGHTHOUSE_CONTEXT_SOURCE.FOCUSED,
    scopeKey: ALERTS_SCOPE_KEY,
    label: toBoundedString(input.name || "Edited alert rule"),
    alertId: safeId,
    trigger: optionalBoundedString(input.trigger),
    enabled: input.enabled,
  };
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

export function buildFindingStatusSummaryContext(
  input: FindingStatusSummaryContextInput,
): LighthouseFindingContextItem {
  const passed = toSafeCount(input.passed);
  const failed = toSafeCount(input.failed);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.FINDING,
    id: "status-summary",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: `${failed} failed / ${passed} passed findings`,
    findingId: "status-summary",
    passed,
    failed,
    newPassed: optionalSafeCount(input.newPassed),
    newFailed: optionalSafeCount(input.newFailed),
  };
}

export function buildFindingSeveritySummaryContext(
  input: FindingSeveritySummaryContextInput,
): LighthouseFindingContextItem {
  const severityCounts = Object.fromEntries(
    Object.entries(input.severityCounts)
      .slice(0, LIGHTHOUSE_CONTEXT_LIMIT.SEVERITY_COUNTS)
      .map(([severity, count]) => [
        toBoundedString(severity),
        toSafeCount(count),
      ]),
  );
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.FINDING,
    id: "severity-summary",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: "Failing findings by severity",
    findingId: "severity-summary",
    severityCounts,
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

export function buildFocusedFindingContext(
  finding: FocusedFindingContextInput,
): LighthouseFindingContextItem {
  const safeFindingId = toBoundedString(finding.findingId);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.FINDING,
    id: safeFindingId,
    source: LIGHTHOUSE_CONTEXT_SOURCE.FOCUSED,
    scopeKey: getLighthouseScopeKey(finding.pathname),
    label: "Focused finding",
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

export function buildFocusedResourceContext(
  resource: FocusedResourceContextInput,
): LighthouseResourceContextItem {
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.RESOURCE,
    id: toBoundedString(resource.id),
    source: LIGHTHOUSE_CONTEXT_SOURCE.FOCUSED,
    scopeKey: getLighthouseScopeKey(resource.pathname),
    label: "Focused resource",
    resourceId: toBoundedString(resource.id),
    resourceUid: toBoundedString(resource.attributes.uid),
    providerUid: optionalBoundedString(resource.providerUid),
    service: toBoundedString(resource.attributes.service),
    region: toBoundedString(resource.attributes.region),
    resourceType: toBoundedString(resource.attributes.type),
    failedFindingsCount: toSafeCount(resource.attributes.failed_findings_count),
  };
}

export function buildServiceSummaryContext(
  input: ServiceSummaryContextInput,
): LighthouseResourceContextItem {
  const safeService = toBoundedString(input.service);
  const safeId = toBoundedString(`service-${safeService}`);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.RESOURCE,
    id: safeId,
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: toBoundedString(`Service: ${safeService}`),
    resourceId: safeId,
    service: safeService,
    failedFindingsCount: toSafeCount(input.failedFindingsCount),
    total: optionalSafeCount(input.total),
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
    mode: input.mode,
    section: optionalBoundedString(input.section),
    region: optionalBoundedString(input.region),
    score,
    scoreDelta: optionalSafeScoreDelta(input.scoreDelta),
    criticalRequirementsCount: optionalSafeCount(
      input.criticalRequirementsCount,
    ),
    worstSection: optionalBoundedString(input.worstSection),
    worstSectionScore:
      input.worstSectionScore === undefined
        ? undefined
        : toSafeScore(input.worstSectionScore),
    totals: hasTotals ? { passed, failed, total } : undefined,
  };
}

export function buildAttackPathContext(
  input: AttackPathContextInput,
): LighthouseAttackPathContextItem {
  const { parameters, redactedParameters } = sanitizeAttackPathParameters(
    input.parameters,
  );
  const graphSummary = summarizeAttackPathGraph(input.graphData);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.ATTACK_PATH,
    id: input.queryId ? "current-query" : "current-scan",
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: toBoundedString(input.queryLabel || "Selected attack-path scan"),
    scanId: toBoundedString(input.scanId),
    queryId: optionalBoundedString(input.queryId ?? undefined),
    ...(input.queryKind
      ? {
          queryKind: input.queryKind,
          canReplayQuery: getCanReplayAttackPathQuery(
            input.queryKind,
            redactedParameters,
          ),
        }
      : {}),
    parameters: Object.keys(parameters).length > 0 ? parameters : undefined,
    ...(redactedParameters.length > 0 ? { redactedParameters } : {}),
    nodeCount: graphSummary?.nodeCount ?? optionalSafeCount(input.nodeCount),
    edgeCount: graphSummary?.edgeCount ?? optionalSafeCount(input.edgeCount),
    ...(graphSummary
      ? {
          connectedComponentCount: graphSummary.connectedComponentCount,
          nodeTypeCounts: graphSummary.nodeTypeCounts,
          relationshipTypeCounts: graphSummary.relationshipTypeCounts,
        }
      : {}),
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

export function buildFilteredProviderContext(
  input: FilteredProviderContextInput,
): LighthouseProviderContextItem {
  const safeId = toBoundedString(input.id);
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.PROVIDER,
    id: safeId,
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: toBoundedString(
      `Provider: ${input.alias || input.uid || "filtered"}`,
    ),
    providerId: safeId,
    providerUid: optionalBoundedString(input.uid),
    providerType: optionalBoundedString(input.type),
  };
}

export function buildProviderGroupContext(
  input: ProviderGroupContextInput,
): LighthouseProviderContextItem {
  return {
    kind: LIGHTHOUSE_CONTEXT_KIND.PROVIDER,
    id: toBoundedString(`group-${input.id}`),
    source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    scopeKey: getLighthouseScopeKey(input.pathname),
    label: toBoundedString(`Provider group: ${input.name}`),
  };
}

function toBoundedString(value: string): string {
  return value.slice(0, LIGHTHOUSE_CONTEXT_LIMIT.STRING_LENGTH);
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

function optionalSafeScoreDelta(value: number | undefined): number | undefined {
  if (value === undefined || !Number.isFinite(value)) return undefined;
  return Math.min(100, Math.max(-100, Math.round(value * 100) / 100));
}

function sanitizeAttackPathParameters(
  parameters: AttackPathContextInput["parameters"],
): SanitizedAttackPathParameters {
  if (!parameters) return { parameters: {}, redactedParameters: [] };

  const safeParameters: Record<string, LighthouseAttackPathParameter> = {};
  const redactedParameters: string[] = [];

  for (const [key, value] of Object.entries(parameters)) {
    if (value === "") continue;

    const isRedacted =
      /password|secret|token|credential|query/i.test(key) ||
      (typeof value === "string" &&
        containsSensitiveLighthouseContextValue(value));
    if (isRedacted) {
      if (
        redactedParameters.length <
        LIGHTHOUSE_CONTEXT_LIMIT.ATTACK_PATH_REDACTED_PARAMETERS
      ) {
        redactedParameters.push(toBoundedString(key));
      }
      continue;
    }

    if (
      Object.keys(safeParameters).length >=
      LIGHTHOUSE_CONTEXT_LIMIT.ATTACK_PATH_PARAMETERS
    ) {
      continue;
    }
    safeParameters[toBoundedString(key)] =
      typeof value === "string" ? toBoundedString(value) : value;
  }

  return {
    parameters: safeParameters,
    redactedParameters: redactedParameters.sort(),
  };
}

interface SanitizedAttackPathParameters {
  parameters: Record<string, LighthouseAttackPathParameter>;
  redactedParameters: string[];
}

interface AttackPathGraphSummary {
  nodeCount: number;
  edgeCount: number;
  connectedComponentCount: number;
  nodeTypeCounts?: Record<string, number>;
  relationshipTypeCounts?: Record<string, number>;
}

function getCanReplayAttackPathQuery(
  queryKind: AttackPathQueryKind | undefined,
  redactedParameters: string[],
): boolean | undefined {
  if (!queryKind) return undefined;
  return (
    queryKind === ATTACK_PATH_QUERY_KIND.PREDEFINED &&
    redactedParameters.length === 0
  );
}

function summarizeAttackPathGraph(
  graphData: AttackPathGraphData | null | undefined,
): AttackPathGraphSummary | undefined {
  if (!graphData) return undefined;

  const edges =
    graphData.edges ??
    graphData.relationships?.map((relationship) => ({
      source: relationship.source,
      target: relationship.target,
      type: relationship.label,
    })) ??
    [];

  return {
    nodeCount: toSafeCount(graphData.nodes.length),
    edgeCount: toSafeCount(edges.length),
    connectedComponentCount: countConnectedComponents(graphData, edges),
    nodeTypeCounts: buildBoundedTypeCounts(
      graphData.nodes.map((node) => node.labels[0]).filter(Boolean),
    ),
    relationshipTypeCounts: buildBoundedTypeCounts(
      edges.map((edge) => edge.type).filter(Boolean),
    ),
  };
}

function countConnectedComponents(
  graphData: AttackPathGraphData,
  edges: ReadonlyArray<Pick<GraphEdge, "source" | "target">>,
): number {
  const nodeIdList = graphData.nodes.map((node) => node.id);
  const nodeIds = new Set(nodeIdList);
  const adjacency = new Map<string, Set<string>>(
    nodeIdList.map((nodeId) => [nodeId, new Set<string>()]),
  );

  for (const edge of edges) {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) continue;
    adjacency.get(edge.source)?.add(edge.target);
    adjacency.get(edge.target)?.add(edge.source);
  }

  const visited = new Set<string>();
  let componentCount = 0;
  for (const nodeId of nodeIdList) {
    if (visited.has(nodeId)) continue;
    componentCount += 1;
    const pending = [nodeId];
    while (pending.length > 0) {
      const current = pending.pop();
      if (!current || visited.has(current)) continue;
      visited.add(current);
      adjacency.get(current)?.forEach((neighbor) => {
        if (!visited.has(neighbor)) pending.push(neighbor);
      });
    }
  }

  return componentCount;
}

function buildBoundedTypeCounts(
  values: string[],
): Record<string, number> | undefined {
  const counts = values.reduce<Record<string, number>>((result, value) => {
    const boundedValue = toBoundedString(value);
    result[boundedValue] = (result[boundedValue] ?? 0) + 1;
    return result;
  }, {});
  const boundedCounts = Object.fromEntries(
    Object.entries(counts)
      .sort(
        ([leftLabel, leftCount], [rightLabel, rightCount]) =>
          rightCount - leftCount || leftLabel.localeCompare(rightLabel),
      )
      .slice(0, LIGHTHOUSE_CONTEXT_LIMIT.ATTACK_PATH_TYPE_COUNTS),
  );

  return Object.keys(boundedCounts).length > 0 ? boundedCounts : undefined;
}
