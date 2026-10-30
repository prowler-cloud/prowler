import { isLighthouseConfigured } from "@/actions/lighthouse-v1";
import { RealtimePageShell } from "@/components/realtime/realtime-page-shell";
import { RealtimeSetupWizard } from "@/components/realtime/setup/realtime-setup-wizard";
import { SearchParamsProps } from "@/types";

const first = (value: string | string[] | undefined) =>
  typeof value === "string" ? value : undefined;

export default async function RealtimeSetupPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolved = await searchParams;

  return (
    <RealtimePageShell>
      {async (providers) => (
        <RealtimeSetupWizard
          providers={providers}
          initialProviderId={first(resolved.provider)}
          // Only used to warn that the code-fix switch has no LLM behind it.
          lighthouseConfigured={Boolean(await isLighthouseConfigured())}
        />
      )}
    </RealtimePageShell>
  );
}
