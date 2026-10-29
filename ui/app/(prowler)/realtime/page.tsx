import { RealtimePageShell } from "@/components/realtime/realtime-page-shell";
import { RealtimeWorkspace } from "@/components/realtime/realtime-workspace";
import { SearchParamsProps } from "@/types";

const first = (value: string | string[] | undefined) =>
  typeof value === "string" ? value : undefined;

export default async function Realtime({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolved = await searchParams;

  return (
    <RealtimePageShell>
      {(providers) => (
        <RealtimeWorkspace
          providers={providers}
          initialProviderId={first(resolved.provider)}
          initialTab={first(resolved.tab)}
        />
      )}
    </RealtimePageShell>
  );
}
