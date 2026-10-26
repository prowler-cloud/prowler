import { FindingProps } from "@/types/components";
import {
  FINDING_TRIAGE_STATUS,
  FindingTriageStatus,
} from "@/types/findings-triage";
import { IssueFinding, IssueTriageNote } from "@/types/issues";
import { JsonApiDocument, JsonApiResource } from "@/types/jsonapi";
import { ResourceProps } from "@/types/resources";

interface IssueFindingAttributes
  extends Pick<
    FindingProps["attributes"],
    "uid" | "check_id" | "check_metadata" | "severity"
  > {
  triage_status?: FindingTriageStatus | null;
}

interface IssueFindingResource extends Pick<FindingProps, "id"> {
  attributes: IssueFindingAttributes;
  relationships: Pick<FindingProps["relationships"], "resources">;
}

interface IssueFindingsDocument
  extends JsonApiDocument<IssueFindingResource[]> {
  included?: JsonApiResource<Pick<ResourceProps["attributes"], "uid">>[];
}

export const toIssueFindings = (
  payload: IssueFindingsDocument | undefined,
): IssueFinding[] | undefined => {
  if (!Array.isArray(payload?.data)) return undefined;
  const resourceUids = new Map(
    (payload.included ?? [])
      .filter((resource) => resource.type === "resources")
      .map((resource) => [resource.id, resource.attributes.uid]),
  );

  return payload.data.flatMap((finding) =>
    (finding.relationships?.resources?.data ?? []).flatMap((resource) => {
      const resourceUid = resourceUids.get(resource.id);
      if (!resourceUid) return [];
      return [
        {
          id: finding.id,
          uid: finding.attributes.uid,
          checkId: finding.attributes.check_id,
          checkTitle:
            finding.attributes.check_metadata?.checktitle ||
            finding.attributes.check_id,
          severity: finding.attributes.severity,
          // A finding nobody has triaged reads as open, as on the Findings page.
          triageStatus:
            finding.attributes.triage_status ?? FINDING_TRIAGE_STATUS.OPEN,
          resourceUid,
        },
      ];
    }),
  );
};

interface IssueTriageNoteResource
  extends JsonApiResource<{ body: string; inserted_at: string }> {
  relationships?: { created_by?: { data: { id: string } | null } };
}

interface IssueTriageNotesDocument
  extends JsonApiDocument<IssueTriageNoteResource[]> {
  included?: JsonApiResource<{ name?: string; email?: string }>[];
}

export const toIssueTriageNotes = (
  payload: IssueTriageNotesDocument | undefined,
): IssueTriageNote[] | undefined => {
  if (!Array.isArray(payload?.data)) return undefined;
  const authors = new Map(
    (payload.included ?? [])
      .filter((resource) => resource.type === "users")
      .map((user) => [user.id, user.attributes.name || user.attributes.email]),
  );

  return payload.data.map((note) => {
    const authorId = note.relationships?.created_by?.data?.id;
    return {
      id: note.id,
      body: note.attributes.body,
      insertedAt: note.attributes.inserted_at,
      author: authorId ? authors.get(authorId) : undefined,
    };
  });
};
