export interface ResourceProps {
  type: "resources";
  id: string;
  attributes: {
    inserted_at: string;
    updated_at: string;
    uid: string;
    name: string;
    region: string;
    service: string;
    tags: Record<string, string>;
    type: string;
    groups: string[] | null;
    failed_findings_count: number;
    details: string | null;
    partition: string | null;
    metadata: Record<string, unknown> | null;
  };
  relationships: {
    provider: {
      data: {
        type: "providers";
        id: string;
        attributes: {
          inserted_at: string;
          updated_at: string;
          provider: string;
          uid: string;
          alias: string | null;
          connection: {
            connected: boolean;
            last_checked_at: string;
          };
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
    findings: {
      meta: {
        count: number;
      };
      data: {
        type: "findings";
        id: string;
        attributes: { status: string; delta: string };
      }[];
    };
  };
  links: {
    self: string;
  };
}

interface ResourceItemProps {
  type: "providers" | "findings";
  id: string;
  attributes: {
    uid: string;
    delta: string;
    status: "PASS" | "FAIL" | "MANUAL";
    status_extended: string;
    severity: "informational" | "low" | "medium" | "high" | "critical";
    check_id: string;
    check_metadata: CheckMetadataProps;
    raw_result: Record<string, unknown>;
    inserted_at: string;
    updated_at: string;
    first_seen_at: string;
    muted: boolean;
  };
  relationships: {
    secret: {
      data: {
        type: string;
        id: string;
      };
    };
    scan: {
      data: {
        type: string;
        id: string;
      };
    };
    provider_groups: {
      meta: {
        count: number;
      };
      data: [];
    };
  };
  links: {
    self: string;
  };
}

interface CheckMetadataProps {
  risk: string;
  notes: string;
  checkid: string;
  provider: string;
  severity: string;
  checktype: string[];
  dependson: string[];
  relatedto: string[];
  categories: string[];
  checktitle: string;
  compliance: unknown;
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
}

interface Meta {
  version: string;
}

export interface ResourceApiResponse {
  data: ResourceProps;
  included: ResourceItemProps[];
  meta: Meta;
}
