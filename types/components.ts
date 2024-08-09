import { SVGProps } from "react";

export type IconSvgProps = SVGProps<SVGSVGElement> & {
  size?: number;
};

export type IconProps = {
  icon: React.FC<IconSvgProps>;
  style?: React.CSSProperties;
};

export interface searchParamsProps {
  searchParams: {
    page?: string;
  };
}

export interface ProviderProps {
  id: string;
  type: "providers";
  attributes: {
    provider: "aws" | "azure" | "gcp";
    provider_id: string;
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

export interface FindingsProps {
  id: string;
  attributes: {
    CheckTitle: string;
    severity: string;
    status: string;
    region: string;
    service: string;
    account: string;
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
