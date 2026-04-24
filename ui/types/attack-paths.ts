/**
 * Attack Paths Feature Types
 * Defines all TypeScript interfaces for the Attack Paths visualization feature
 */

// Scan state constants
export const SCAN_STATES = {
  AVAILABLE: "available",
  SCHEDULED: "scheduled",
  EXECUTING: "executing",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;

export type ScanState = (typeof SCAN_STATES)[keyof typeof SCAN_STATES];

// Attack Path Scan - Relationship Data
export interface RelationshipData {
  type: string;
  id: string;
}

export interface RelationshipWrapper {
  data: RelationshipData;
}

export interface ScanRelationships {
  provider: RelationshipWrapper;
  scan: RelationshipWrapper;
  task: RelationshipWrapper;
}

// Provider type constants
export const PROVIDER_TYPES = {
  AWS: "aws",
  AZURE: "azure",
  GCP: "gcp",
} as const;

export type ProviderType = (typeof PROVIDER_TYPES)[keyof typeof PROVIDER_TYPES];

// Attack Path Scan Response
export interface AttackPathScanAttributes {
  state: ScanState;
  progress: number;
  graph_data_ready: boolean;
  provider_alias: string;
  provider_type: ProviderType;
  provider_uid: string;
  inserted_at: string;
  started_at: string;
  completed_at: string | null;
  duration: number | null;
}

export interface AttackPathScan {
  type: "attack-paths-scans";
  id: string;
  attributes: AttackPathScanAttributes;
  relationships: ScanRelationships;
}

export interface PaginationLinks {
  first: string;
  last: string;
  next: string | null;
  prev: string | null;
}

export interface AttackPathScansResponse {
  data: AttackPathScan[];
  links: PaginationLinks;
}

// Data type constants
export const DATA_TYPES = {
  STRING: "string",
  NUMBER: "number",
  BOOLEAN: "boolean",
} as const;

type DataType = (typeof DATA_TYPES)[keyof typeof DATA_TYPES];

export const QUERY_PARAMETER_INPUT_TYPES = {
  TEXT: "text",
  TEXTAREA: "textarea",
  CODE_EDITOR: "code-editor",
} as const;

export type QueryParameterInputType =
  (typeof QUERY_PARAMETER_INPUT_TYPES)[keyof typeof QUERY_PARAMETER_INPUT_TYPES];

export const ATTACK_PATH_QUERY_IDS = {
  CUSTOM: "__custom-open-cypher__",
} as const;

// Query Types
export interface AttackPathQueryParameter {
  name: string;
  label: string;
  data_type: DataType;
  description: string;
  placeholder?: string;
  required?: boolean;
  input_type?: QueryParameterInputType;
  editor_language?: "openCypher";
  requirement_badge?: string;
}

export interface AttackPathQueryAttribution {
  text: string;
  link: string;
}

export interface AttackPathQueryDocumentationLink {
  text: string;
  link: string;
}

export interface AttackPathQueryAttributes {
  name: string;
  short_description: string;
  description: string;
  provider: string;
  parameters: AttackPathQueryParameter[];
  attribution: AttackPathQueryAttribution | null;
  documentation_link?: AttackPathQueryDocumentationLink | null;
}

export interface AttackPathQuery {
  type: "attack-paths-scans";
  id: string;
  attributes: AttackPathQueryAttributes;
}

export interface AttackPathQueriesResponse {
  data: AttackPathQuery[];
}

export interface AttackPathCartographySchemaAttributes {
  id: string;
  provider: string;
  cartography_version: string;
  schema_url: string;
  raw_schema_url: string;
}

export interface AttackPathCartographySchema {
  type: "attack-paths-cartography-schemas";
  id: string;
  attributes: AttackPathCartographySchemaAttributes;
}

export interface AttackPathCartographySchemaResponse {
  data: AttackPathCartographySchema;
}

// Graph Data Types
// Property values from graph nodes can be any primitive type or arrays
export type GraphNodePropertyValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | string[]
  | number[];

export interface GraphNodeProperties {
  [key: string]: GraphNodePropertyValue;
}

export interface GraphNode {
  id: string;
  labels: string[]; // e.g., ["S3Bucket"], ["EC2Instance"], ["ProwlerFinding"]
  properties: GraphNodeProperties;
  findings?: string[]; // IDs of finding nodes connected via HAS_FINDING edges
  resources?: string[]; // IDs of resource nodes connected via HAS_FINDING edges
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  properties?: GraphNodeProperties;
}

export interface GraphRelationship {
  id: string;
  label: string;
  source: string;
  target: string;
  properties?: GraphNodeProperties;
}

export interface AttackPathGraphData {
  nodes: GraphNode[];
  edges?: GraphEdge[];
  relationships?: GraphRelationship[];
}

export interface QueryResultAttributes {
  nodes: GraphNode[];
  relationships?: GraphRelationship[];
}

export interface QueryResultData {
  type: "attack-paths-query-run-requests";
  id: string | null;
  attributes: QueryResultAttributes;
}

export interface AttackPathQueryResult {
  data: QueryResultData;
}

export interface AttackPathQueryError {
  error: string;
  status: number;
}

// Wizard State Types
export interface WizardState {
  currentStep: 1 | 2;
  selectedScanId: string | null;
  selectedQuery: string | null;
  queryParameters: Record<string, string | number | boolean>;
}

// Graph State Types
export interface GraphState {
  data: AttackPathGraphData | null;
  selectedNodeId: string | null;
  loading: boolean;
  error: string | null;
}

// Provider Integration
export interface ProviderWithScanStatus {
  id: string;
  alias: string;
  provider: string;
  scan: AttackPathScan;
  connected: boolean;
}

// API Request/Response Helpers
export interface QueryRequestAttributes {
  id: string;
  parameters?: Record<string, string | number | boolean>;
}

export interface ExecuteQueryRequestData {
  type: "attack-paths-query-run-requests";
  attributes: QueryRequestAttributes;
}

export interface ExecuteQueryRequest {
  data: ExecuteQueryRequestData;
}

export interface ExecuteCustomQueryRequestAttributes {
  query: string;
}

export interface ExecuteCustomQueryRequestData {
  type: "attack-paths-custom-query-run-requests";
  attributes: ExecuteCustomQueryRequestAttributes;
}

export interface ExecuteCustomQueryRequest {
  data: ExecuteCustomQueryRequestData;
}
