import type { FindingProps } from "@/types/components";
import type {
  FindingTriageManualStatus,
  FindingTriageStatus,
} from "@/types/findings-triage";
import type { IssueFinding, IssueTriageNote } from "@/types/issues";
import type { JsonApiDocument, JsonApiResource } from "@/types/jsonapi";
import type { ResourceProps } from "@/types/resources";
import type { UserAttributes, UserData } from "@/types/users";

export interface IssueFindingAttributes
  extends Pick<
    FindingProps["attributes"],
    "uid" | "check_id" | "check_metadata" | "severity"
  > {
  triage_status?: FindingTriageStatus | null;
}

export interface IssueFindingResource extends Pick<FindingProps, "id"> {
  attributes: IssueFindingAttributes;
  relationships: Pick<FindingProps["relationships"], "resources">;
}

export interface IssueFindingsDocument
  extends JsonApiDocument<IssueFindingResource[]> {
  included?: JsonApiResource<Pick<ResourceProps["attributes"], "uid">>[];
}

export interface IssueTriageNoteAttributes
  extends Pick<IssueTriageNote, "body"> {
  inserted_at: IssueTriageNote["insertedAt"];
}

export interface IssueTriageNoteAuthorRelationship {
  data: Pick<UserData, "id"> | null;
}

export interface IssueTriageNoteRelationships {
  created_by?: IssueTriageNoteAuthorRelationship;
}

export interface IssueTriageNoteResource
  extends JsonApiResource<IssueTriageNoteAttributes> {
  relationships?: IssueTriageNoteRelationships;
}

export interface IssueTriageNotesDocument
  extends JsonApiDocument<IssueTriageNoteResource[]> {
  included?: JsonApiResource<Partial<Pick<UserAttributes, "name" | "email">>>[];
}

/** What the issue panel draws: resources, a capped findings preview and the scan it came from. */
export interface IssueEvidence {
  resources: string[];
  /** Undefined when the findings could not be loaded. */
  findings: IssueFinding[] | undefined;
  /** The issue has more unique findings than the preview holds. */
  findingsTruncated: boolean;
  scanId?: string;
  providerId?: string;
}

export type IssueWriteResult =
  | { success: true }
  | { error: string; status?: number };

export interface UpdateIssueTriageInput {
  status: FindingTriageManualStatus;
  note?: string;
}

export const ISSUE_TRIAGE_WRITE_METHOD = {
  UPDATE: "PATCH",
  ADD_NOTE: "POST",
} as const;

export type IssueTriageWriteMethod =
  (typeof ISSUE_TRIAGE_WRITE_METHOD)[keyof typeof ISSUE_TRIAGE_WRITE_METHOD];
