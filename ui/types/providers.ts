import type { ScheduleFrequency } from "./schedules";

export const PROVIDER_TYPES = [
  "aws",
  "azure",
  "gcp",
  "kubernetes",
  "m365",
  "mongodbatlas",
  "github",
  "googleworkspace",
  "iac",
  "image",
  "oraclecloud",
  "alibabacloud",
  "cloudflare",
  "openstack",
  "vercel",
  "okta",
] as const;

export type ProviderType = (typeof PROVIDER_TYPES)[number];

export const PROVIDER_DISPLAY_NAMES: Record<ProviderType, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "Google Cloud",
  kubernetes: "Kubernetes",
  m365: "Microsoft 365",
  mongodbatlas: "MongoDB Atlas",
  github: "GitHub",
  googleworkspace: "Google Workspace",
  iac: "Infrastructure as Code",
  image: "Container Registry",
  oraclecloud: "Oracle Cloud Infrastructure",
  alibabacloud: "Alibaba Cloud",
  cloudflare: "Cloudflare",
  openstack: "OpenStack",
  vercel: "Vercel",
  okta: "Okta",
};

export function getProviderDisplayName(providerId: string): string {
  return (
    PROVIDER_DISPLAY_NAMES[providerId.toLowerCase() as ProviderType] ||
    providerId
  );
}

export interface ProviderProps {
  id: string;
  type: "providers";
  attributes: {
    provider: ProviderType;
    uid: string;
    alias: string;
    status: "completed" | "pending" | "cancelled";
    resources: number;
    connection: {
      connected: boolean;
      last_checked_at: string;
    };
    scanner_args: {
      only_logs: boolean;
      excluded_checks: string[];
      aws_retries_max_attempts: number;
    };
    inserted_at: string;
    updated_at: string;
    scan_frequency?: ScheduleFrequency | null;
    scan_hour?: number | null;
    scan_day_of_week?: number | null;
    scan_day_of_month?: number | null;
    scan_interval_hours?: number | null;
    scan_timezone?: string | null;
    scan_enabled?: boolean | null;
    next_scan_at?: string | null;
    last_scan_at?: string | null;
    created_by: {
      object: string;
      id: string;
    };
  };
  relationships: {
    secret: {
      data: {
        type: string;
        id: string;
      } | null;
    };
    provider_groups: {
      meta: {
        count: number;
      };
      data: Array<{
        type: string;
        id: string;
      }>;
    };
  };
  groupNames?: string[];
}

export interface ProviderEntity {
  provider: ProviderType;
  uid: string;
  alias: string | null;
}

export interface GroupFilterEntity {
  name: string;
  uid: string;
}

export interface ProviderConnectionStatus {
  label: string;
  value: string;
}

export interface ProvidersApiResponse {
  links: {
    first: string;
    last: string;
    next: string | null;
    prev: string | null;
  };
  data: ProviderProps[];
  included?: Array<{
    type: string;
    id: string;
    attributes: Record<string, unknown>;
    relationships?: Record<string, unknown>;
  }>;
  meta: {
    pagination: {
      page: number;
      pages: number;
      count: number;
    };
    version: string;
  };
}
