import { Spacer } from "@heroui/spacer";

import { LighthouseSettings, LLMProvidersTable } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function ChatbotConfigPage() {
  return (
    <ContentLayout title="LLM Configuration">
      <LLMProvidersTable />
      <Spacer y={8} />
      <LighthouseSettings />
    </ContentLayout>
  );
}
