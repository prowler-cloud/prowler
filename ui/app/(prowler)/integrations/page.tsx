import { ContentLayout } from "@/components/shadcn/content-layout";

import { IntegrationsContent } from "./integrations-content";

export default async function Integrations() {
  return (
    <ContentLayout title="Integrations" icon="lucide:puzzle">
      <IntegrationsContent />
    </ContentLayout>
  );
}
