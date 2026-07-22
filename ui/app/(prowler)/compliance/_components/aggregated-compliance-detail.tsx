import Image from "next/image";
import type { ComponentProps, ReactNode } from "react";

import {
  ClientAccordionWrapper,
  RequirementsStatusCard,
  TopFailedSectionsCard,
} from "@/components/compliance";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { Card } from "@/components/shadcn/card/card";
import type { RequirementsTotals } from "@/types/compliance";

interface AggregatedComplianceDetailProps {
  compliancetitle: string;
  logoPath?: ComponentProps<typeof Image>["src"];
  title: ReactNode;
  description: ReactNode;
  reportAction: ReactNode;
  filters: ReactNode;
  totals: RequirementsTotals;
  coverage: ReactNode;
  topFailed: ComponentProps<typeof TopFailedSectionsCard>;
  accordionItems: AccordionItemProps[];
  initialExpandedKeys: string[];
}

export const AggregatedComplianceDetail = ({
  compliancetitle,
  logoPath,
  title,
  description,
  reportAction,
  filters,
  totals,
  coverage,
  topFailed,
  accordionItems,
  initialExpandedKeys,
}: AggregatedComplianceDetailProps) => (
  <div className="flex flex-col gap-8">
    <Card variant="base" padding="lg">
      <div className="flex w-full flex-col gap-4">
        <div className="flex w-full items-center justify-between gap-4">
          <div className="flex min-w-0 items-center gap-4">
            {logoPath && (
              <div className="relative h-12 w-12 shrink-0">
                <Image
                  src={logoPath}
                  alt={`${compliancetitle} logo`}
                  fill
                  sizes="48px"
                  className="border-border-neutral-secondary bg-bg-neutral-primary rounded-lg border object-contain"
                />
              </div>
            )}
            <div className="flex min-w-0 flex-col gap-0.5">
              {title}
              {description}
            </div>
          </div>
          <div className="shrink-0">{reportAction}</div>
        </div>
        {filters}
      </div>
    </Card>

    <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-[minmax(280px,400px)_minmax(280px,360px)_1fr]">
      <RequirementsStatusCard
        pass={totals.pass}
        fail={totals.fail}
        manual={totals.manual}
      />
      {coverage}
      <TopFailedSectionsCard {...topFailed} />
    </div>

    <ClientAccordionWrapper
      items={accordionItems}
      defaultExpandedKeys={initialExpandedKeys}
      scrollToKey={initialExpandedKeys[0]}
    />
  </div>
);
