import type { RegistryCatalogArtifact } from "@/types/registry";

/** Installation eligibility comes from catalog capabilities, never the package name. */
export function isRegistryArtifactInstallable(
  artifact: Pick<RegistryCatalogArtifact, "hasProvider" | "isBuiltin">,
): boolean {
  return artifact.hasProvider === true && artifact.isBuiltin === false;
}
