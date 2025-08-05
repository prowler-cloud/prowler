import { getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { LighthouseIcon } from "@/components/icons/Icons";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export default async function AIChatbot() {
  const config = await getLighthouseConfig();

  const hasConfig = !!config;
  const isActive = config?.attributes?.is_active ?? false;

  return (
    <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon />}>
      <Chat hasConfig={hasConfig} isActive={isActive} />
    </ContentLayout>
  );
}
