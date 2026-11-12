import { Tags } from "lucide-react";

import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function Workloads() {
  return (
    <ContentLayout title="Workloads" icon={<Tags />}>
      <p>Workloads</p>
    </ContentLayout>
  );
}
