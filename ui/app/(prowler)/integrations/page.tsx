import React from "react";

import { ContentLayout } from "@/components/ui";
import { IntegrationsContent } from "./integrations-content";

export default function Integrations() {
  return (
    <ContentLayout title="Integrations" icon="tabler:puzzle">
      <IntegrationsContent />
    </ContentLayout>
  );
}
