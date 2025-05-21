import { getAIKey } from "@/actions/lighthouse/lighthouse";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export const AIChatbot = async () => {
  const apiKey = await getAIKey();

  return (
    <ContentLayout title="Cloud Security Analyst" icon="lucide:bot">
      <Chat hasApiKey={!!apiKey} />
    </ContentLayout>
  );
};

export default AIChatbot;
