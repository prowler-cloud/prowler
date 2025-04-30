import { ContentLayout } from "@/components/ui";

import Chat from "./chat";

export default function AIChatbot() {
  return (
    <div>
      <ContentLayout title="Cloud Security Analyst" icon="lucide:bot">
        <Chat />
      </ContentLayout>
    </div>
  );
}
