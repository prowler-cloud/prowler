import { isLighthouseConfigured } from "@/actions/lighthouse-v1";
import { RealtimePageShell } from "@/components/realtime/realtime-page-shell";
import { RealtimeSettings } from "@/components/realtime/realtime-settings";
import { SearchParamsProps } from "@/types";

const first = (value: string | string[] | undefined) =>
  typeof value === "string" ? value : undefined;

export default async function RealtimeSettingsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolved = await searchParams;

  return (
    <RealtimePageShell>
      {async (providers) => (
        <RealtimeSettings
          providers={providers}
          initialProviderId={first(resolved.provider)}
          // Only used to warn that the code-fix switch has no LLM behind it.
          lighthouseConfigured={Boolean(await isLighthouseConfigured())}
        />
      )}
    </RealtimePageShell>
  );
}
