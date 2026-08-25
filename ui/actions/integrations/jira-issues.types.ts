import type { JsonApiDocument, JsonApiResource } from "@/types/jsonapi";

export interface JiraIssueAttributes {
  inserted_at: string;
  updated_at: string;
  finding_uid: string;
  finding_id: string;
  issue_key: string;
  issue_id: string;
  issue_url: string;
  project_key: string;
  issue_status: string;
  issue_status_category: string;
  status_synced_at: string | null;
}

interface JsonApiRelationshipRef {
  data?: { type: string; id: string } | null;
}

export type JiraIssueResource = JsonApiResource<JiraIssueAttributes> & {
  relationships?: {
    provider?: JsonApiRelationshipRef;
    integration?: JsonApiRelationshipRef;
  };
};

export type JiraIssuesResponse = JsonApiDocument<JiraIssueResource[]>;
