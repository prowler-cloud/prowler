import { getAIKey } from "@/actions/lighthouse/lighthouse";
import { ContentLayout } from "@/components/ui";

import Chat from "./chat";

export default async function AIChatbot() {
  const apiKey = await getAIKey();

  return (
    <ContentLayout title="Cloud Security Analyst" icon="lucide:bot">
      <Chat hasApiKey={!!apiKey} />
    </ContentLayout>
  );
}
