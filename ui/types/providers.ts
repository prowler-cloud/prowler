export const PROVIDER_TYPES = [
  "aws",
  "azure",
  "gcp",
  "kubernetes",
  "m365",
  "github",
] as const;

export type ProviderType = (typeof PROVIDER_TYPES)[number];

interface ProviderConnection {
  connected: boolean;
  last_checked_at: string;
}

interface ScannerArgs {
  only_logs: boolean;
  excluded_checks: string[];
  aws_retries_max_attempts: number;
}

interface CreatedBy {
  object: string;
  id: string;
}

interface ProviderAttributes {
  provider: ProviderType;
  uid: string;
  alias: string;
  status: "completed" | "pending" | "cancelled";
  resources: number;
  connection: ProviderConnection;
  scanner_args: ScannerArgs;
  inserted_at: string;
  updated_at: string;
  created_by: CreatedBy;
}

interface ApiEntity {
  type: string;
  id: string;
}

interface RelationshipData {
  data: ApiEntity | null;
}

interface ProviderGroupMeta {
  count: number;
}

interface ProviderGroupRelationship {
  meta: ProviderGroupMeta;
  data: ApiEntity[];
}

interface ProviderRelationships {
  secret: RelationshipData;
  provider_groups: ProviderGroupRelationship;
}

export interface ProviderProps {
  id: string;
  type: "providers";
  attributes: ProviderAttributes;
  relationships: ProviderRelationships;
  groupNames?: string[];
}

export interface ProviderEntity {
  uid: string;
  alias: string | null;
  provider: ProviderType;
}

export interface ProviderConnectionStatus {
  label: string;
  value: string;
}

interface ProviderFinding {
  pass: number;
  fail: number;
  manual: number;
  total: number;
}

interface ProviderResources {
  total: number;
}

interface ProviderOverviewAttributes {
  findings: ProviderFinding;
  resources: ProviderResources;
}

interface ProviderOverviewData {
  type: "provider-overviews";
  id: ProviderType;
  attributes: ProviderOverviewAttributes;
}

interface ResponseMeta {
  version: string;
}

export interface ProviderOverviewProps {
  data: ProviderOverviewData[];
  meta: ResponseMeta;
}

interface PaginationMeta {
  page: number;
  pages: number;
  count: number;
}

interface ApiResponseMeta {
  pagination: PaginationMeta;
  version: string;
}

interface ApiLinks {
  first: string;
  last: string;
  next: string | null;
  prev: string | null;
}

interface IncludedEntity {
  type: string;
  id: string;
  attributes?: any;
  relationships?: any;
}

export interface ProvidersApiResponse {
  links: ApiLinks;
  data: ProviderProps[];
  included?: IncludedEntity[];
  meta: ApiResponseMeta;
}
