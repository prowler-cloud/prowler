import { FindingProps } from "@/types/components";
import { IssueFinding } from "@/types/issues";
import { JsonApiDocument, JsonApiResource } from "@/types/jsonapi";
import { ResourceProps } from "@/types/resources";

interface IssueFindingResource extends Pick<FindingProps, "id"> {
  attributes: Pick<
    FindingProps["attributes"],
    "check_id" | "check_metadata" | "severity"
  >;
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
          checkId: finding.attributes.check_id,
          checkTitle:
            finding.attributes.check_metadata?.checktitle ||
            finding.attributes.check_id,
          severity: finding.attributes.severity,
          resourceUid,
        },
      ];
    }),
  );
};
