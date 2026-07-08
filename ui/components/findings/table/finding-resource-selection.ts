import { FindingResourceRow } from "@/types";

export function canMuteFindingResource(resource: FindingResourceRow): boolean {
  return resource.status === "FAIL" && !resource.isMuted;
}
