import Link from "next/link";

import { CrossProviderFrameworkCard } from "@/app/(prowler)/compliance/_components/cross-provider-framework-card";
import type { CrossProviderFrameworkSummary } from "@/app/(prowler)/compliance/_types";
import { ComplianceFrameworkGrid } from "@/components/compliance/compliance-framework-grid";
import { Button, Card, CardContent } from "@/components/shadcn";

import { SectionHeader } from "./section-header";

/** The AI frameworks as the Compliance page's universal framework cards. */
export const AiCompliance = ({
  frameworks,
}: {
  frameworks: CrossProviderFrameworkSummary[];
}) => (
  <Card variant="base" className="w-full min-w-0">
    <SectionHeader
      title="Compliance frameworks"
      description="Universal frameworks aggregated across every compatible provider type, using the latest completed scan of each provider."
      aside={
        <Button asChild variant="link" size="link-sm">
          <Link href="/compliance">Open in Compliance</Link>
        </Button>
      }
    />
    <CardContent>
      <ComplianceFrameworkGrid>
        {frameworks.map((framework) => (
          <CrossProviderFrameworkCard
            key={framework.complianceId}
            {...framework}
          />
        ))}
      </ComplianceFrameworkGrid>
    </CardContent>
  </Card>
);
