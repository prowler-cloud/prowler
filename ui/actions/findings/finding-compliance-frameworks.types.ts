import type { JsonApiDocument, JsonApiResource } from "@/types/jsonapi";

export interface FindingComplianceFrameworkAttributes {
  compliance_id: string;
  provider_type: string;
  scope: string;
  framework: string;
  name: string;
  version: string;
  in_watchlist: boolean;
}

export type FindingComplianceFrameworkResource =
  JsonApiResource<FindingComplianceFrameworkAttributes>;

export type FindingComplianceFrameworksResponse = JsonApiDocument<
  FindingComplianceFrameworkResource[]
>;
