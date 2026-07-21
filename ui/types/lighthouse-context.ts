export const LIGHTHOUSE_CONTEXT_KIND = {
  PAGE: "page",
  FINDING: "finding",
  RESOURCE: "resource",
  COMPLIANCE: "compliance",
  ATTACK_PATH: "attack_path",
  SCAN: "scan",
  PROVIDER: "provider",
} as const;

export type LighthouseContextKind =
  (typeof LIGHTHOUSE_CONTEXT_KIND)[keyof typeof LIGHTHOUSE_CONTEXT_KIND];

export const LIGHTHOUSE_CONTEXT_SOURCE = {
  AUTOMATIC: "automatic",
  SELECTION: "selection",
  MANUAL: "manual",
} as const;

export type LighthouseContextSource =
  (typeof LIGHTHOUSE_CONTEXT_SOURCE)[keyof typeof LIGHTHOUSE_CONTEXT_SOURCE];

export const LIGHTHOUSE_CONTEXT_TRANSPORT = {
  INLINE: "inline",
} as const;

export type LighthouseContextTransport =
  (typeof LIGHTHOUSE_CONTEXT_TRANSPORT)[keyof typeof LIGHTHOUSE_CONTEXT_TRANSPORT];

export const LIGHTHOUSE_PAGE_ID = {
  OVERVIEW: "overview",
  FINDINGS: "findings",
  RESOURCES: "resources",
  COMPLIANCE: "compliance",
  COMPLIANCE_DETAIL: "compliance-detail",
  ATTACK_PATHS: "attack-paths",
  SCANS: "scans",
  PROVIDERS: "providers",
  OTHER: "other",
} as const;

export type LighthousePageId =
  (typeof LIGHTHOUSE_PAGE_ID)[keyof typeof LIGHTHOUSE_PAGE_ID];

export interface LighthouseContextFilters {
  [key: string]: string[];
}

export interface LighthouseContextItemBase {
  id: string;
  source: LighthouseContextSource;
  scopeKey: string;
  label: string;
}

export interface LighthousePageContextItem extends LighthouseContextItemBase {
  kind: typeof LIGHTHOUSE_CONTEXT_KIND.PAGE;
  path: string;
  filters?: LighthouseContextFilters;
}

export interface LighthouseFindingContextItem
  extends LighthouseContextItemBase {
  kind: typeof LIGHTHOUSE_CONTEXT_KIND.FINDING;
  findingId: string;
  checkId?: string;
  severity?: string;
  status?: string;
  providerUid?: string;
  resourceUid?: string;
  region?: string;
  total?: number;
}

export interface LighthouseResourceContextItem
  extends LighthouseContextItemBase {
  kind: typeof LIGHTHOUSE_CONTEXT_KIND.RESOURCE;
  resourceId: string;
  resourceUid?: string;
  providerUid?: string;
  service?: string;
  region?: string;
  resourceType?: string;
  failedFindingsCount?: number;
  total?: number;
}

export interface LighthouseComplianceTotals {
  passed?: number;
  failed?: number;
  total?: number;
}

export interface LighthouseComplianceContextItem
  extends LighthouseContextItemBase {
  kind: typeof LIGHTHOUSE_CONTEXT_KIND.COMPLIANCE;
  framework: string;
  version?: string;
  scanId?: string;
  providerUid?: string;
  mode?: string;
  section?: string;
  region?: string;
  score?: number;
  totals?: LighthouseComplianceTotals;
}

export type LighthouseAttackPathParameter = string | number | boolean;

export interface LighthouseAttackPathParameters {
  [key: string]: LighthouseAttackPathParameter;
}

export interface LighthouseAttackPathContextItem
  extends LighthouseContextItemBase {
  kind: typeof LIGHTHOUSE_CONTEXT_KIND.ATTACK_PATH;
  scanId?: string;
  queryId?: string;
  parameters?: LighthouseAttackPathParameters;
  nodeCount?: number;
  edgeCount?: number;
  selectedNodeId?: string;
  selectedNodeType?: string;
}

export interface LighthouseScanContextItem extends LighthouseContextItemBase {
  kind: typeof LIGHTHOUSE_CONTEXT_KIND.SCAN;
  scanId?: string;
  state?: string;
  providerUid?: string;
  total?: number;
}

export interface LighthouseProviderContextItem
  extends LighthouseContextItemBase {
  kind: typeof LIGHTHOUSE_CONTEXT_KIND.PROVIDER;
  providerId?: string;
  providerUid?: string;
  providerType?: string;
  total?: number;
}

export type LighthouseContextItem =
  | LighthousePageContextItem
  | LighthouseFindingContextItem
  | LighthouseResourceContextItem
  | LighthouseComplianceContextItem
  | LighthouseAttackPathContextItem
  | LighthouseScanContextItem
  | LighthouseProviderContextItem;

export interface LighthouseContextEnvelope {
  schemaVersion: 1;
  transport: LighthouseContextTransport;
  items: LighthouseContextItem[];
}
