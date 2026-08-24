import type { RegistryTenantArtifact } from "@/types/registry";

interface RegistryOverviewProps {
  availableArtifacts: {
    name?: string;
    normalizedName: string;
    providers: string[];
  }[];
  metrics: Record<
    "providers" | "availableArtifacts" | "myArtifacts" | "officialArtifacts",
    number
  >;
  selectedId: string;
  tenantArtifacts: RegistryTenantArtifact[];
}

export function RegistryOverview({
  availableArtifacts,
  metrics,
  selectedId,
  tenantArtifacts,
}: RegistryOverviewProps) {
  const group = selectedId.startsWith("group:")
    ? selectedId.slice("group:".length)
    : undefined;
  const rows =
    selectedId === "root:my-artifacts"
      ? tenantArtifacts
      : group === "multi-provider"
        ? availableArtifacts.filter((artifact) => artifact.providers.length > 1)
        : group
          ? availableArtifacts.filter((artifact) =>
              artifact.providers.includes(group),
            )
          : availableArtifacts;
  return (
    <section aria-labelledby="registry-overview-title">
      <h1 id="registry-overview-title" className="text-xl font-semibold">
        {selectedId === "root:my-artifacts"
          ? "My artifacts"
          : group
            ? `${group} artifacts`
            : "Registry overview"}
      </h1>
      <div className="mt-6 grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <p>Providers: {metrics.providers}</p>
        <p>Available artifacts: {metrics.availableArtifacts}</p>
        <p>My artifacts: {metrics.myArtifacts}</p>
        <p>Official artifacts: {metrics.officialArtifacts}</p>
      </div>
      <p className="text-text-neutral-secondary mt-6 text-sm">
        {rows.length} artifact{rows.length === 1 ? "" : "s"} in this view.
      </p>
      {rows.length ? (
        <ul className="mt-3 space-y-2 text-sm">
          {rows.map((artifact) => (
            <li key={artifact.normalizedName}>
              {("name" in artifact ? artifact.name : undefined) ??
                artifact.normalizedName}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-text-neutral-secondary mt-3 text-sm">
          No artifacts match this complete catalog view.
        </p>
      )}
    </section>
  );
}
