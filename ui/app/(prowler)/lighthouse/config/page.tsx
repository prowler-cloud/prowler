import { getLighthouseConfig } from "@/actions/lighthouse";
import { ChatbotConfig } from "@/components/lighthouse";

export const dynamic = "force-dynamic";

export default async function ChatbotConfigPage() {
  const response = await getLighthouseConfig();

  const initialValues = response?.data?.attributes
    ? {
        model: response.data.attributes.model,
        apiKey: response.data.attributes.api_key || "",
        businessContext: response.data.attributes.business_context || "",
      }
    : {
        model: "gpt-4o",
        apiKey: "",
        businessContext: "",
      };

  const configExists = !!response;

  return (
    <ChatbotConfig initialValues={initialValues} configExists={configExists} />
  );
}
