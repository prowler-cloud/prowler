import { LighthouseSettings, LLMProvidersTable } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function ChatbotConfigPage() {
  return (
    <ContentLayout title="LLM Configuration">
      <LLMProvidersTable />
      <div className="h-8" />
      <LighthouseSettings />
    </ContentLayout>
  );
}
