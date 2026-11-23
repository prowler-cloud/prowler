import { Puzzle } from "lucide-react";

import { ContentLayout } from "@/components/shadcn/content-layout";

import { IntegrationsContent } from "./integrations-content";

export default async function Integrations() {
  return (
    <ContentLayout title="Integrations" icon={<Puzzle />}>
      <IntegrationsContent />
    </ContentLayout>
  );
}
