import { SVGProps } from "react";

export type IconSvgProps = SVGProps<SVGSVGElement> & {
  size?: number;
};

export type IconProps = {
  icon: React.FC<IconSvgProps>;
  style?: React.CSSProperties;
};

export type NextUIVariants =
  | "solid"
  | "faded"
  | "bordered"
  | "light"
  | "flat"
  | "ghost"
  | "shadow";

export type NextUIColors =
  | "primary"
  | "secondary"
  | "success"
  | "warning"
  | "danger"
  | "default";

export interface SearchParamsProps {
  [key: string]: string | string[] | undefined;
}
export interface ProviderProps {
  id: string;
  type: "providers";
  attributes: {
    provider: "aws" | "azure" | "gcp";
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
    created_by: {
      object: string;
      id: string;
    };
  };
}

export interface FindingProps {
  id: string;
  attributes: {
    CheckTitle: string;
    severity: "critical" | "high" | "medium" | "low";
    status: "fail" | "success" | "muted";
    region: string;
    service: string;
    account: string;
  };
  card: {
    resourceId: string;
    resourceLink: string;
    resourceARN: string;
    checkId: string;
    checkLink: string;
    type: string[];
    scanTime: string;
    findingId: string;
    findingLink: string;
    details: string;
    riskLink: string;
    riskDetails: string;
    recommendationLink: string;
    recommendationDetails: string;
    referenceInformation: string;
    referenceLink: string;
  };
}

export interface MetaDataProps {
  pagination: {
    page: number;
    pages: number;
    count: number;
  };
  version: string;
}

export interface UserProps {
  id: string;
  email: string;
  name: string;
  role: string;
  dateAdded: string;
  status: "active" | "inactive";
}
