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

export interface ApiError {
  detail: string;
  status: string;
  source: {
    pointer: string;
  };
  code: string;
}

export interface ProviderProps {
  id: string;
  type: "providers";
  attributes: {
    provider: "aws" | "azure" | "gcp" | "kubernetes";
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

export interface ScanProps {
  type: "Scan";
  id: string;
  attributes: {
    name: string;
    trigger: "scheduled" | "manual";
    state:
      | "available"
      | "scheduled"
      | "executing"
      | "completed"
      | "failed"
      | "cancelled";
    unique_resource_count: number;
    progress: number;
    scanner_args: {
      only_logs?: boolean;
      excluded_checks?: string[];
      aws_retries_max_attempts?: number;
    } | null;
    duration: number;
    started_at: string;
    completed_at: string;
    scheduled_at: string;
  };
  relationships: {
    provider: {
      data: {
        id: string;
        type: "Provider";
      };
    };
    task: {
      data: {
        id: string;
        type: "Task";
      };
    };
  };
}

export interface FindingsProps {
  type: "Findings";
  id: string;
  attributes: {
    uid: string;
    delta: "new" | "changed" | null;
    status: "PASS" | "FAIL" | "MANUAL" | "MUTED";
    status_extended: string;
    severity: "informational" | "low" | "medium" | "high" | "critical";
    check_id: string;
    check_metadata: {
      check_id: string;
      metadata: {
        Risk: string;
        Notes: string;
        CheckID: string;
        Provider: string;
        Severity: "informational" | "low" | "medium" | "high" | "critical";
        CheckType: string[];
        DependsOn: string[];
        RelatedTo: string[];
        Categories: string[];
        CheckTitle: string;
        RelatedUrl: string;
        Description: string;
        Remediation: {
          Code: {
            CLI: string;
            Other: string;
            NativeIaC: string;
            Terraform: string;
          };
          Recommendation: {
            Url: string;
            Text: string;
          };
        };
        ServiceName: string;
        ResourceType: string;
        SubServiceName: string;
        ResourceIdTemplate: string;
      };
    };
    raw_result: {
      impact: string;
      status: "PASS" | "FAIL" | "MANUAL" | "MUTED";
      severity: "informational" | "low" | "medium" | "high" | "critical";
    };
    inserted_at: string;
    updated_at: string;
  };
  relationships: {
    scan: {
      data: {
        type: "Scan";
        id: string;
      };
    };
    resources: {
      data: {
        type: "Resource";
        id: string;
      }[];
      meta: {
        count: number;
      };
    };
  };
  links: {
    self: string;
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
