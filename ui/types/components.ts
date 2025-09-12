import { LucideIcon } from "lucide-react";
import { SVGProps } from "react";

import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export type IconSvgProps = SVGProps<SVGSVGElement> & {
  size?: number;
};

export type IconProps = {
  icon: React.FC<IconSvgProps>;
  style?: React.CSSProperties;
};

export type IconComponent = LucideIcon | React.FC<IconSvgProps>;

export type SubmenuProps = {
  href: string;
  target?: string;
  label: string;
  active?: boolean;
  icon: IconComponent;
  disabled?: boolean;
  onClick?: () => void;
};

export type MenuProps = {
  href: string;
  label: string;
  active?: boolean;
  icon: IconComponent;
  submenus?: SubmenuProps[];
  defaultOpen?: boolean;
  target?: string;
  tooltip?: string;
};

export type GroupProps = {
  groupLabel: string;
  menus: MenuProps[];
};

export interface CollapseMenuButtonProps {
  icon: IconComponent;
  label: string;
  submenus: SubmenuProps[];
  defaultOpen: boolean;
  isOpen: boolean | undefined;
}

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

export interface PermissionInfo {
  field: string;
  label: string;
  description: string;
}
export interface FindingsByStatusData {
  data: {
    type: "findings-overview";
    id: string;
    attributes: {
      fail: number;
      pass: number;
      muted: number;
      total: number;
      fail_new: number;
      pass_new: number;
      muted_new: number;
      [key: string]: number;
    };
  };
  meta: {
    version: string;
  };
}
export interface ManageGroupPayload {
  data: {
    type: "provider-groups";
    id: string;
    attributes?: {
      name: string;
    };
    relationships?: {
      providers?: { data: Array<{ id: string; type: string }> };
      roles?: { data: Array<{ id: string; type: string }> };
    };
  };
}
export interface ProviderGroup {
  type: "provider-groups";
  id: string;
  attributes: {
    name: string;
    inserted_at: string;
    updated_at: string;
  };
  relationships: {
    providers: {
      meta: {
        count: number;
      };
      data: {
        type: string;
        id: string;
      }[];
    };
    roles: {
      meta: {
        count: number;
      };
      data: {
        type: string;
        id: string;
      }[];
    };
  };
  links: {
    self: string;
  };
}

export interface ProviderGroupsResponse {
  links: {
    first: string;
    last: string;
    next: string | null;
    prev: string | null;
  };
  data: ProviderGroup[];
  meta: {
    pagination: {
      page: number;
      pages: number;
      count: number;
    };
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
  [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: string;
  [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: string;
  [ProviderCredentialFields.AWS_SESSION_TOKEN]: string;
  [ProviderCredentialFields.PROVIDER_ID]: string;
};

export type AWSCredentialsRole = {
  [ProviderCredentialFields.ROLE_ARN]?: string;
  [ProviderCredentialFields.AWS_ACCESS_KEY_ID]?: string;
  [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]?: string;
  [ProviderCredentialFields.AWS_SESSION_TOKEN]?: string;
  [ProviderCredentialFields.EXTERNAL_ID]?: string;
  [ProviderCredentialFields.ROLE_SESSION_NAME]?: string;
  [ProviderCredentialFields.SESSION_DURATION]?: number;
  [ProviderCredentialFields.CREDENTIALS_TYPE]?:
    | "aws-sdk-default"
    | "access-secret-key";
};

export type AzureCredentials = {
  [ProviderCredentialFields.CLIENT_ID]: string;
  [ProviderCredentialFields.CLIENT_SECRET]: string;
  [ProviderCredentialFields.TENANT_ID]: string;
  [ProviderCredentialFields.PROVIDER_ID]: string;
};

export type M365Credentials = {
  [ProviderCredentialFields.CLIENT_ID]: string;
  [ProviderCredentialFields.CLIENT_SECRET]: string;
  [ProviderCredentialFields.TENANT_ID]: string;
  [ProviderCredentialFields.USER]?: string;
  [ProviderCredentialFields.PASSWORD]?: string;
  [ProviderCredentialFields.PROVIDER_ID]: string;
};

export type GCPDefaultCredentials = {
  client_id: string;
  client_secret: string;
  refresh_token: string;
  [ProviderCredentialFields.PROVIDER_ID]: string;
};

export type GCPServiceAccountKey = {
  [ProviderCredentialFields.SERVICE_ACCOUNT_KEY]: string;
  [ProviderCredentialFields.PROVIDER_ID]: string;
};

export type KubernetesCredentials = {
  [ProviderCredentialFields.KUBECONFIG_CONTENT]: string;
  [ProviderCredentialFields.PROVIDER_ID]: string;
};

export type CredentialsFormSchema =
  | AWSCredentials
  | AzureCredentials
  | GCPDefaultCredentials
  | GCPServiceAccountKey
  | KubernetesCredentials
  | M365Credentials;

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
    role?: {
      data: {
        type: "roles";
        id: string;
      };
      attributes?: {
        name: string;
        manage_users?: boolean;
        manage_account?: boolean;
        manage_billing?: boolean;
        manage_providers?: boolean;
        manage_integrations?: boolean;
        manage_scans?: boolean;
        permission_state?: "unlimited" | "limited" | "none";
      };
    };
  };
  links: {
    self: string;
  };
  roles?: {
    id: string;
    name: string;
  }[];
}

export interface Role {
  type: "roles";
  id: string;
  attributes: {
    name: string;
    manage_users: boolean;
    manage_account: boolean;
    manage_billing: boolean;
    manage_providers: boolean;
    manage_integrations: boolean;
    manage_scans: boolean;
    unlimited_visibility: boolean;
    permission_state: "unlimited" | "limited" | "none";
    inserted_at: string;
    updated_at: string;
  };
  relationships: {
    provider_groups: {
      meta: {
        count: number;
      };
      data: {
        type: string;
        id: string;
      }[];
    };
    users: {
      meta: {
        count: number;
      };
      data: {
        type: string;
        id: string;
      }[];
    };
    invitations: {
      meta: {
        count: number;
      };
      data: {
        type: string;
        id: string;
      }[];
    };
  };
  links: {
    self: string;
  };
}

export interface RolesProps {
  links: {
    first: string;
    last: string;
    next: string | null;
    prev: string | null;
  };
  data: Role[];
  meta: {
    pagination: {
      page: number;
      pages: number;
      count: number;
    };
    version: string;
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
      role: {
        name: string;
      };
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
    role: {
      name: string;
    };
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
    roles: {
      meta: {
        count: number;
      };
      data: Array<{
        type: "roles";
        id: string;
      }>;
    };
  };
  roles: {
    id: string;
    name: string;
  }[];
}

export interface FindingsResponse {
  data: FindingProps[];
  meta: MetaDataProps;
}

export interface FindingProps {
  type: "findings";
  id: string;
  attributes: {
    uid: string;
    delta: "new" | "changed" | null;
    status: "PASS" | "FAIL" | "MANUAL";
    status_extended: string;
    severity: "informational" | "low" | "medium" | "high" | "critical";
    check_id: string;
    muted: boolean;
    muted_reason?: string;
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
    first_seen_at: string | null;
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
        inserted_at: string;
        completed_at: string;
        scheduled_at: string | null;
        next_scan_at: string;
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
    itemsPerPage?: Array<number>;
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
