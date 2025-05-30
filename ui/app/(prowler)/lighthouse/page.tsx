import { getAIKey } from "@/actions/lighthouse/lighthouse";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export default async function AIChatbot() {
  const apiKey = await getAIKey();

  return (
    <ContentLayout title="Cloud Security Analyst" icon="lucide:bot">
      <Chat hasApiKey={!!apiKey} />
    </ContentLayout>
  );
}
