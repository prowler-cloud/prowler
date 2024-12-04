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

export interface FindingsByStatusData {
  data: {
    type: "findings-overview";
    id: string;
    attributes: {
      fail: number;
      pass: number;
      total: number;
      fail_new: number;
      pass_new: number;
      [key: string]: number;
    };
  };
  meta: {
    version: string;
  };
}

export interface FindingsSeverityOverview {
  data: {
    type: "findings-severity-overview";
    id: string;
    attributes: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      informational: number;
    };
  };
  meta: {
    version: string;
  };
}

export interface ProviderOverviewProps {
  data: {
    type: "provider-overviews";
    id: "aws" | "gcp" | "azure" | "kubernetes";
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

export interface TaskDetails {
  attributes: {
    state: string;
    completed_at: string;
    result: {
      exc_type?: string;
      exc_message?: string[];
      exc_module?: string;
    };
    task_args: {
      scan_id: string;
      provider_id: string;
      checks_to_execute: string[];
    };
  };
}
export type AWSCredentials = {
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_session_token: string;
  secretName: string;
  providerId: string;
};

export type AWSCredentialsRole = {
  role_arn: string;
  aws_access_key_id?: string;
  aws_secret_access_key?: string;
  aws_session_token?: string;
  external_id?: string;
  role_session_name?: string;
  session_duration?: number;
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

export type KubernetesCredentials = {
  kubeconfig_content: string;
  secretName: string;
  providerId: string;
};

export type CredentialsFormSchema =
  | AWSCredentials
  | AzureCredentials
  | GCPCredentials
  | KubernetesCredentials;

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
export interface CompliancesOverview {
  links: {
    first: string;
    last: string;
    next: string | null;
    prev: string | null;
  };
  data: ComplianceOverviewData[];
  meta: {
    pagination: {
      page: number;
      pages: number;
      count: number;
    };
    version: string;
  };
}

export interface ComplianceOverviewData {
  type: "compliance-overviews";
  id: string;
  attributes: {
    inserted_at: string;
    compliance_id: string;
    framework: string;
    version: string;
    requirements_status: {
      passed: number;
      failed: number;
      manual: number;
      total: number;
    };
    region: string;
    provider_type: string;
  };
  relationships: {
    scan: {
      data: {
        type: "scans";
        id: string;
      };
    };
  };
  links: {
    self: string;
  };
}

export interface InvitationProps {
  type: "invitations";
  id: string;
  attributes: {
    inserted_at: string;
    updated_at: string;
    email: string;
    state: string;
    token: string;
    expires_at: string;
  };
  relationships: {
    inviter: {
      data: {
        type: "users";
        id: string;
      };
    };
  };
  links: {
    self: string;
  };
}
export interface UserProfileProps {
  data: {
    type: "users";
    id: string;
    attributes: {
      name: string;
      email: string;
      company_name: string;
      date_joined: string;
    };
    relationships: {
      memberships: {
        meta: {
          count: number;
        };
        data: Array<{
          type: "memberships";
          id: string;
        }>;
      };
    };
  };
  meta: {
    version: string;
  };
}

export interface UserProps {
  type: "users";
  id: string;
  attributes: {
    name: string;
    email: string;
    company_name: string;
    date_joined: string;
  };
  relationships: {
    memberships: {
      meta: {
        count: number;
      };
      data: Array<{
        type: "memberships";
        id: string;
      }>;
    };
  };
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
  type: "scans";
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
    next_scan_at: string;
  };
  relationships: {
    provider: {
      data: {
        id: string;
        type: "providers";
      };
    };
    task: {
      data: {
        id: string;
        type: "tasks";
      };
    };
  };
  providerInfo?: {
    provider: "aws" | "azure" | "gcp" | "kubernetes";
    uid: string;
    alias: string;
  };
}

export interface FindingProps {
  type: "findings";
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
        type: "resources";
        id: string;
      }[];
    };
    scan: {
      data: {
        type: "scans";
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
        type: "resources";
        id: string;
      }[];
      id: string;
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
            type: "providers";
            id: string;
          };
        };
        findings: {
          meta: {
            count: number;
          };
          data: {
            type: "findings";
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
        type: "providers";
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
            type: "provider-secrets";
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
