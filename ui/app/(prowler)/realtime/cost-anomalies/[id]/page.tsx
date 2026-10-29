import { AnomalyDetail } from "@/components/realtime/anomaly-detail";
import { RealtimePageShell } from "@/components/realtime/realtime-page-shell";
import { DEMO_ANOMALY_ID, DEMO_ANOMALY_SLUG } from "@/lib/realtime/demo";
import { SearchParamsProps } from "@/types";

const first = (value: string | string[] | undefined) =>
  typeof value === "string" ? value : undefined;

/** `service|region`, URL-encoded; Next may hand it over still encoded. */
const decode = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

export default async function RealtimeCostAnomalyPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<SearchParamsProps>;
}) {
  const [{ id }, resolved] = await Promise.all([params, searchParams]);

  return (
    <RealtimePageShell>
      {() => (
        <AnomalyDetail
          // The sample anomaly has one fixed page; its data is made up.
          anomalyId={id === DEMO_ANOMALY_SLUG ? DEMO_ANOMALY_ID : decode(id)}
          providerId={first(resolved.provider) ?? ""}
          demo={id === DEMO_ANOMALY_SLUG}
        />
      )}
    </RealtimePageShell>
  );
}
