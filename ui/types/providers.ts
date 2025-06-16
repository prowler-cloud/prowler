export type ProviderType = "aws" | "azure" | "m365" | "gcp" | "kubernetes";

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

export interface ProviderOverviewProps {
  data: {
    type: "provider-overviews";
    id: ProviderType;
    attributes: {
      findings: {
        pass: number;
        fail: number;
        manual: number;
        total: number;
      };
      resources: {
        total: number;
      };
    };
  }[];
  meta: {
    version: string;
  };
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
    attributes: any;
    relationships?: any;
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
