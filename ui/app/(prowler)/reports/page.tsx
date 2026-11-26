import { FileChartLine } from "lucide-react";
import { redirect } from "next/navigation";

import { getAllProviders } from "@/actions/providers";
import { PostureChangeReportButton } from "@/app/(prowler)/providers/_components/posture-change-report-button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { isCloud } from "@/lib/shared/env";

export default async function ReportsPage() {
  // The report API only exists in Prowler Cloud.
  if (!isCloud()) {
    redirect("/");
  }

  const providers = (await getAllProviders())?.data ?? [];

  return (
    <ContentLayout title="Reports" icon={<FileChartLine />}>
      <Card variant="base" padding="lg">
        <CardHeader>
          <CardTitle>Posture change report</CardTitle>
          <CardDescription>
            A PDF, in English or Spanish, with how one provider changed between
            two dates: failed findings by severity, inventory and scan coverage,
            compliance with the latest CIS benchmark first, Prowler ThreatScore
            and exploitability issues.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <PostureChangeReportButton providers={providers} />
        </CardContent>
      </Card>
    </ContentLayout>
  );
}
