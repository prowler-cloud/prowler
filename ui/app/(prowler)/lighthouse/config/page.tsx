import { getLighthouseConfig } from "@/actions/lighthouse";
import { ChatbotConfig } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function ChatbotConfigPage() {
  const lighthouseConfig = await getLighthouseConfig();
  const initialValues = lighthouseConfig
    ? {
        model: lighthouseConfig.model,
        apiKey: lighthouseConfig.api_key || "",
        businessContext: lighthouseConfig.business_context || "",
      }
    : {
        model: "gpt-4o",
        apiKey: "",
        businessContext: "",
      };

  const configExists = !!lighthouseConfig;

  return (
    <ContentLayout title="Configure Lighthouse AI" icon="lucide:settings">
      <ChatbotConfig
        initialValues={initialValues}
        configExists={configExists}
      />
    </ContentLayout>
  );
}
