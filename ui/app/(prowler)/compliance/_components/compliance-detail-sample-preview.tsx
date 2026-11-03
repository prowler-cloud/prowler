import {
  ClientAccordionWrapper,
  ComplianceHeader,
  RequirementsStatusCard,
  TopFailedSectionsCard,
} from "@/components/compliance";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Card } from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { SAMPLE_SCAN } from "@/lib/sample-preview/sample-compliance";
import { getSampleComplianceDetail } from "@/lib/sample-preview/sample-compliance-requirements";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import type { SamplePreviewActive } from "@/lib/sample-preview/sample-preview-state";
import type { Framework, RequirementsTotals } from "@/types/compliance";

interface ComplianceDetailSamplePreviewProps {
  state: SamplePreviewActive;
  compliancetitle: string;
  complianceId: string;
  version?: string;
  /** CIS profile level, applied by the mapper like on the real page. */
  filter?: string;
}

/** A sample framework's detail: real catalog, sample statuses, no reports or Lighthouse. */
export async function ComplianceDetailSamplePreview({
  state,
  compliancetitle,
  complianceId,
  version,
  filter,
}: ComplianceDetailSamplePreviewProps) {
  const detail = await getSampleComplianceDetail(complianceId);
  const formattedTitle = compliancetitle.split("-").join(" ");
  const title = version ? `${formattedTitle} - ${version}` : formattedTitle;

  const mapper = getComplianceMapper(
    detail?.attributesData.data[0]?.attributes.framework,
  );
  const data: Framework[] = detail
    ? mapper.mapComplianceData(
        detail.attributesData,
        { data: detail.requirements },
        filter,
      )
    : [];
  const totals = data.reduce<RequirementsTotals>(
    (acc, framework) => ({
      pass: acc.pass + framework.pass,
      fail: acc.fail + framework.fail,
      manual: acc.manual + framework.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );
  const topFailed = mapper.getTopFailedSections(data);

  return (
    <ContentLayout title={title}>
      <SamplePreviewBanner
        state={state}
        page={SAMPLE_PREVIEW_PAGE.COMPLIANCE}
      />
      <Card variant="base" className="mb-6 w-full gap-4 p-4 md:p-5">
        <ComplianceHeader
          scans={[]}
          uniqueRegions={[]}
          showSearch={false}
          framework={compliancetitle}
          showProviders={false}
          logoPath={getComplianceIcon(compliancetitle)}
          complianceTitle={compliancetitle}
          selectedScan={SAMPLE_SCAN}
        />
      </Card>
      <div className="flex flex-col gap-8">
        <div className="grid grid-cols-1 gap-6 md:grid-cols-[minmax(280px,400px)_1fr]">
          <RequirementsStatusCard
            pass={totals.pass}
            fail={totals.fail}
            manual={totals.manual}
          />
          <TopFailedSectionsCard
            sections={topFailed.items}
            dataType={topFailed.type}
            prepopulated={topFailed.prepopulated}
          />
        </div>
        {/* Requirement findings come from the sample records via the sample scan id. */}
        <ClientAccordionWrapper
          items={mapper.toAccordionItems(data, SAMPLE_SCAN.id)}
          defaultExpandedKeys={[]}
        />
      </div>
    </ContentLayout>
  );
}
