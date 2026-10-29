import { ShieldAlert } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { getIssue } from "@/actions/issues";
import { IssueDetail } from "@/components/issues/issue-detail";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { EntityInfo } from "@/components/shadcn/entities";
import { FeatureFlagRoute } from "@/components/shared/feature-flag-route";
import { FEATURE_FLAG } from "@/lib/feature-flags";
import { VERDICTS } from "@/lib/issues/verdicts";
import { isCloud } from "@/lib/shared/env";

/**
 * One issue on its own URL, so a path can be shared or linked from a ticket.
 * The body is the same detail the list opens in place.
 */
export default async function IssuePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  if (!isCloud()) notFound();
  const { id } = await params;
  const issue = (await getIssue(id))?.data;
  // handleApiResponse resolves {error, status} on a 4xx: no data is no issue.
  if (!issue?.attributes) notFound();

  const { attributes, relationships } = issue;
  const verdict = VERDICTS.find((item) => item.id === attributes.verdict);

  return (
    <ContentLayout title="Issue" icon={<ShieldAlert />}>
      <FeatureFlagRoute flag={FEATURE_FLAG.ISSUES}>
        <div className="flex min-w-0 flex-col gap-4">
          <Button asChild variant="link" size="link-sm" className="self-start">
            <Link href="/issues">← All issues</Link>
          </Button>
          <Card variant="base" className="min-w-0 gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={verdict?.variant ?? "tag"}>
                {verdict?.label ?? attributes.verdict}
              </Badge>
              <span className="text-text-neutral-tertiary text-xs">
                {attributes.pattern}
              </span>
            </div>
            <h2 className="text-text-neutral-primary text-lg font-semibold break-words">
              {attributes.title}
            </h2>
            <EntityInfo
              cloudProvider={attributes.cloud}
              entityAlias={attributes.account}
            />
            <IssueDetail
              id={issue.id}
              issue={attributes}
              scanId={relationships?.scan?.data?.id}
              providerId={relationships?.provider?.data?.id}
            />
          </Card>
        </div>
      </FeatureFlagRoute>
    </ContentLayout>
  );
}
