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

export type AWSCredentials = {
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_session_token: string;
  secretName: string;
  providerId: string;
};

export type AzureCredentials = {
  client_id: string;
  client_secret: string;
  tenant_id: string;
  secretName: string;
  providerId: string;
};

export type GCPCredentials = {
  client_id: string;
  client_secret: string;
  refresh_token: string;
  secretName: string;
  providerId: string;
};

export type CredentialsFormSchema =
  | AWSCredentials
  | AzureCredentials
  | GCPCredentials;

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

export interface FindingProps {
  type: "Finding";
  id: string;
  attributes: {
    uid: string;
    delta: "new" | "changed" | null;
    status: "PASS" | "FAIL" | "MANUAL" | "MUTED";
    status_extended: string;
    severity: "informational" | "low" | "medium" | "high" | "critical";
    check_id: string;
    check_metadata: {
      risk: string;
      notes: string;
      checkid: string;
      provider: string;
      severity: "informational" | "low" | "medium" | "high" | "critical";
      checktype: string[];
      dependson: string[];
      relatedto: string[];
      categories: string[];
      checktitle: string;
      compliance: string | null;
      relatedurl: string;
      description: string;
      remediation: {
        code: {
          cli: string;
          other: string;
          nativeiac: string;
          terraform: string;
        };
        recommendation: {
          url: string;
          text: string;
        };
      };
      servicename: string;
      checkaliases: string[];
      resourcetype: string;
      subservicename: string;
      resourceidtemplate: string;
    };
    raw_result: object | null;
    inserted_at: string;
    updated_at: string;
  };
  relationships: {
    resources: {
      data: {
        type: "Resource";
        id: string;
      }[];
    };
    scan: {
      data: {
        type: "Scan";
        id: string;
      };
      attributes: {
        name: string;
        trigger: string;
        state: string;
        unique_resource_count: number;
        progress: number;
        scanner_args: {
          checks_to_execute: string[];
        };
        duration: number;
        started_at: string;
        completed_at: string;
        scheduled_at: string | null;
      };
    };
    resource: {
      data: {
        type: "Resource";
        id: string;
      }[];
      attributes: {
        uid: string;
        name: string;
        region: string;
        service: string;
        tags: Record<string, string>;
        type: string;
        inserted_at: string;
        updated_at: string;
      };
      relationships: {
        provider: {
          data: {
            type: "Provider";
            id: string;
          };
        };
        findings: {
          meta: {
            count: number;
          };
          data: {
            type: "Finding";
            id: string;
          }[];
        };
      };
      links: {
        self: string;
      };
    };
    provider: {
      data: {
        type: "Provider";
        id: string;
      };
      attributes: {
        provider: string;
        uid: string;
        alias: string;
        connection: {
          connected: boolean;
          last_checked_at: string;
        };
        inserted_at: string;
        updated_at: string;
      };
      relationships: {
        secret: {
          data: {
            type: "ProviderSecret";
            id: string;
          };
        };
      };
      links: {
        self: string;
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
