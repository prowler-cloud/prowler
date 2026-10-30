import { CostAnomalySettings } from "@/components/realtime/cost-anomaly-settings";
import { RealtimePageShell } from "@/components/realtime/realtime-page-shell";
import { SearchParamsProps } from "@/types";

const first = (value: string | string[] | undefined) =>
  typeof value === "string" ? value : undefined;

export default async function RealtimeCostAnomalySettingsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolved = await searchParams;

  return (
    <RealtimePageShell>
      {(providers) => (
        <CostAnomalySettings
          providers={providers}
          initialProviderId={first(resolved.provider)}
        />
      )}
    </RealtimePageShell>
  );
}
