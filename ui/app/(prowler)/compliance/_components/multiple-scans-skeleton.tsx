import { ComplianceFrameworkGrid } from "@/components/compliance/compliance-framework-grid";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { Accordion } from "@/components/shadcn/accordion/Accordion";
import { Card, CardContent } from "@/components/shadcn/card/card";
import {
  Section,
  SectionContent,
  SectionDescription,
  SectionHeader,
  SectionTitle,
} from "@/components/shadcn/section/section";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

const FILTER_SKELETON_COUNT = 3;
const FRAMEWORK_CARD_SKELETON_COUNT = 3;
const PROVIDER_GROUP_SKELETON_COUNT = 2;
const PROVIDER_CHIP_SKELETON_COUNT = 5;

const FrameworkCardSkeleton = () => (
  <Card
    variant="base"
    padding="md"
    data-skeleton-kind="framework-card"
    aria-hidden="true"
  >
    <CardContent>
      <div className="flex w-full flex-col gap-3">
        <div className="flex items-center gap-3">
          <Skeleton className="size-10 shrink-0" />
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-3 w-1/2" />
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <Skeleton className="h-3 w-12" />
            <Skeleton className="h-3 w-8" />
          </div>
          <Skeleton className="h-2.5 w-full" />
        </div>

        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-1.5">
            {Array.from({ length: PROVIDER_CHIP_SKELETON_COUNT }).map(
              (_, index) => (
                <Skeleton key={index} className="size-[18px] rounded-sm" />
              ),
            )}
          </div>
          <Skeleton className="h-3 w-28" />
        </div>
      </div>
    </CardContent>
  </Card>
);

const providerGroupItems: AccordionItemProps[] = Array.from({
  length: PROVIDER_GROUP_SKELETON_COUNT,
}).map((_, index) => ({
  key: `provider-skeleton-${index}`,
  title: (
    <span className="flex min-w-0 items-center gap-3" aria-hidden="true">
      <Skeleton className="size-[18px] shrink-0 rounded-sm" />
      <Skeleton className="h-4 w-20 shrink-0" />
      <Skeleton className="h-3 w-36" />
    </span>
  ),
  content: null,
  items: [],
  isDisabled: true,
}));

export const CrossProviderOverviewSkeleton = () => (
  <div
    role="status"
    aria-label="Loading across provider types"
    aria-busy="true"
    className="flex flex-col gap-6"
  >
    <div className="flex flex-wrap items-center gap-4" aria-hidden="true">
      {Array.from({ length: FILTER_SKELETON_COUNT }).map((_, index) => (
        <Skeleton
          key={index}
          data-skeleton-kind="filter"
          className="h-10 w-full sm:max-w-[280px] sm:min-w-[180px] sm:flex-1"
        />
      ))}
    </div>

    <Section>
      <SectionHeader>
        <SectionTitle>Across provider types</SectionTitle>
        <SectionDescription>
          Universal frameworks aggregated across every compatible provider type,
          using the latest completed scan of each provider.
        </SectionDescription>
      </SectionHeader>
      <SectionContent>
        <ComplianceFrameworkGrid>
          {Array.from({ length: FRAMEWORK_CARD_SKELETON_COUNT }).map(
            (_, index) => (
              <FrameworkCardSkeleton key={index} />
            ),
          )}
        </ComplianceFrameworkGrid>
      </SectionContent>
    </Section>
  </div>
);

export const CrossAccountOverviewSkeleton = () => (
  <Section role="status" aria-label="Loading across providers" aria-busy="true">
    <SectionHeader>
      <SectionTitle>Across providers</SectionTitle>
      <SectionDescription>
        Single-provider frameworks aggregated across every provider of the same
        type, using each provider&apos;s latest completed scan. Expand a
        provider type to browse its frameworks.
      </SectionDescription>
    </SectionHeader>
    <SectionContent>
      <Accordion items={providerGroupItems} selectionMode="multiple" />
    </SectionContent>
  </Section>
);
