import { getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export default async function AIChatbot() {
  const config = await getLighthouseConfig();

  const hasConfig = !!config;
  const isActive = config?.attributes?.is_active ?? false;

  return (
    <ContentLayout title="Lighthouse" icon="lucide:bot">
      <Chat hasConfig={hasConfig} isActive={isActive} />
    </ContentLayout>
  );
}
