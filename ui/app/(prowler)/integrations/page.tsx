import { SamlIntegrationCard } from "@/components/integrations";
import { ContentLayout } from "@/components/ui";

export default function Integrations() {
  return (
    <ContentLayout title="Integrations" icon="lucide:puzzle">
      <SamlIntegrationCard />
    </ContentLayout>
  );
}
