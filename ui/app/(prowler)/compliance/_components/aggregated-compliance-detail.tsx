import Image from "next/image";
import type { ComponentProps, ReactNode } from "react";

import {
  ClientAccordionWrapper,
  RequirementsStatusCard,
  TopFailedSectionsCard,
} from "@/components/compliance";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { Card } from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";
import type { RequirementsTotals } from "@/types/compliance";

interface AggregatedComplianceDetailProps {
  compliancetitle: string;
  logoPath?: ComponentProps<typeof Image>["src"];
  title: ReactNode;
  description: ReactNode;
  headerLink?: ReactNode;
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
  headerLink,
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
        <div
          data-slot="aggregated-compliance-header"
          className={cn(
            "grid w-full items-center gap-x-4 gap-y-3",
            logoPath
              ? "grid-cols-[auto_minmax(0,1fr)] sm:grid-cols-[auto_minmax(0,1fr)_auto]"
              : "grid-cols-1 sm:grid-cols-[minmax(0,1fr)_auto]",
          )}
        >
          {logoPath && (
            <div className="relative col-start-1 row-start-1 h-12 w-12 shrink-0 sm:row-span-2">
              <Image
                src={logoPath}
                alt={`${compliancetitle} logo`}
                fill
                sizes="48px"
                className="border-border-neutral-tertiary rounded-lg border bg-slate-50 object-contain"
              />
            </div>
          )}
          {headerLink ? (
            <div
              data-slot="aggregated-compliance-heading"
              className={cn(
                "contents sm:row-span-2 sm:row-start-1 sm:grid sm:min-w-0 sm:grid-cols-[minmax(0,max-content)_auto] sm:items-center sm:justify-start sm:gap-x-4 sm:gap-y-3",
                logoPath ? "sm:col-start-2" : "sm:col-start-1",
              )}
            >
              <div
                data-slot="aggregated-compliance-title"
                className={cn(
                  "row-start-1 min-w-0 truncate",
                  logoPath ? "col-start-2" : "col-start-1",
                  "sm:col-start-1 sm:row-start-1",
                )}
              >
                {title}
              </div>
              <div
                data-slot="aggregated-compliance-description"
                className={cn(
                  "row-start-2 min-w-0 sm:col-span-2 sm:col-start-1 sm:row-start-2",
                  logoPath ? "col-span-2 col-start-1" : "col-start-1",
                )}
              >
                {description}
              </div>
              <div
                data-slot="aggregated-compliance-header-link"
                className={cn(
                  "row-start-3 justify-self-start sm:col-span-1 sm:col-start-2 sm:row-start-1 sm:shrink-0",
                  logoPath ? "col-span-2 col-start-1" : "col-start-1",
                )}
              >
                {headerLink}
              </div>
            </div>
          ) : (
            <>
              <div
                data-slot="aggregated-compliance-title"
                className={cn(
                  "row-start-1 min-w-0 truncate",
                  logoPath ? "col-start-2" : "col-start-1",
                )}
              >
                {title}
              </div>
              <div
                data-slot="aggregated-compliance-description"
                className={cn(
                  "row-start-2 min-w-0",
                  logoPath
                    ? "col-span-2 col-start-1 sm:col-span-1 sm:col-start-2"
                    : "col-start-1",
                )}
              >
                {description}
              </div>
            </>
          )}
          <div
            data-slot="aggregated-compliance-report-action"
            className={cn(
              "justify-self-start sm:row-span-2 sm:row-start-1 sm:justify-self-end",
              headerLink ? "row-start-4" : "row-start-3",
              logoPath
                ? "col-span-2 col-start-1 sm:col-span-1 sm:col-start-3"
                : "col-start-1 sm:col-start-2",
            )}
          >
            {reportAction}
          </div>
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
      scrollToKey={initialExpandedKeys.at(-1)}
    />
  </div>
);
