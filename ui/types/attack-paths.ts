/**
 * Attack Paths Feature Types
 * Defines all TypeScript interfaces for the Attack Paths visualization feature
 */

// Scan state constants
const SCAN_STATES = {
  EXECUTING: "executing",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;

type ScanState = (typeof SCAN_STATES)[keyof typeof SCAN_STATES];

// Attack Path Scan Response
export interface AttackPathScanAttributes {
  state: ScanState;
  progress: number;
  inserted_at: string;
  started_at: string;
  completed_at: string | null;
  duration: number | null;
}

export interface AttackPathScan {
  type: "attack-paths-scans";
  id: string;
  attributes: AttackPathScanAttributes;
  relationships: {
    provider: {
      data: {
        type: "providers";
        id: string;
      };
    };
    scan: {
      data: {
        type: "scans";
        id: string;
      };
    };
    task: {
      data: {
        type: "tasks";
        id: string;
      };
    };
  };
}

export interface AttackPathScansResponse {
  data: AttackPathScan[];
  links: {
    first: string;
    last: string;
    next: string | null;
    prev: string | null;
  };
}

// Data type constants
const DATA_TYPES = {
  STRING: "string",
  NUMBER: "number",
  BOOLEAN: "boolean",
} as const;

type DataType = (typeof DATA_TYPES)[keyof typeof DATA_TYPES];

// Query Types
export interface AttackPathQueryParameter {
  name: string;
  label: string;
  data_type: DataType;
  description: string;
  placeholder?: string;
  required?: boolean;
}

export interface AttackPathQueryAttributes {
  name: string;
  description: string;
  provider: string;
  parameters: AttackPathQueryParameter[];
}

export interface AttackPathQuery {
  type: "attack-paths-scans";
  id: string;
  attributes: AttackPathQueryAttributes;
}

export interface AttackPathQueriesResponse {
  data: AttackPathQuery[];
}

// Graph Data Types
// Property values from graph nodes can be any primitive type
export type GraphNodePropertyValue =
  | string
  | number
  | boolean
  | null
  | undefined;

export interface GraphNodeProperties {
  [key: string]: GraphNodePropertyValue;
}

export interface GraphNode {
  id: string;
  labels: string[]; // e.g., ["S3Bucket"], ["EC2Instance"], ["ProwlerFinding"]
  properties: GraphNodeProperties;
}

export interface GraphEdge {
  id: string;
  source: string | object;
  target: string | object;
  type: string;
  properties?: GraphNodeProperties;
}

export interface AttackPathGraphData {
  nodes: GraphNode[];
  edges?: GraphEdge[];
}

export interface AttackPathQueryResult {
  data: {
    type: "attack-paths-query-run-request";
    id: null;
    attributes: AttackPathGraphData;
  };
}

// Node Detail Types
export interface NodeDetailData extends GraphNode {
  relatedFindings?: Array<{
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    status: "PASS" | "FAIL" | "MANUAL";
  }>;
  incomingEdges?: GraphEdge[];
  outgoingEdges?: GraphEdge[];
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
  zoomLevel: number;
  panX: number;
  panY: number;
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
export interface ExecuteQueryRequest {
  data: {
    type: "attack-paths-query-run-request";
    attributes: {
      id: string;
      parameters?: Record<string, string | number | boolean>;
    };
  };
}
