"use client";

import { Snippet } from "@nextui-org/react";
import { InfoIcon } from "lucide-react";
import { useState } from "react";

import { getFindingById } from "@/actions/findings";
import { FindingDetail } from "@/components/findings/table/finding-detail";
import { BreadcrumbNavigation, CustomBreadcrumbItem } from "@/components/ui";
import {
  DateWithTime,
  EntityInfoShort,
  InfoField,
} from "@/components/ui/entities";
import { SeverityBadge, StatusFindingBadge } from "@/components/ui/table";
import { createDict } from "@/lib";
import { FindingProps, ResourceProps } from "@/types";

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
};

const Section = ({
  title,
  children,
  action,
}: {
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) => (
  <div className="flex flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
    <div className="flex items-center justify-between">
      <h3 className="text-md font-medium text-gray-800 dark:text-prowler-theme-pale/90">
        {title}
      </h3>
      {action && <div>{action}</div>}
    </div>
    {children}
  </div>
);

const TagsSection = ({ tags }: { tags: Record<string, string> }) => {
  const tagEntries = Object.entries(tags || {});

  if (tagEntries.length === 0) {
    return (
      <Section title="Resource Tags">
        <p className="text-sm text-gray-600 dark:text-prowler-theme-pale/80">
          No tags found for this resource.
        </p>
      </Section>
    );
  }

  return (
    <Section title="Resource Tags">
      <div className="flex flex-wrap justify-between">
        {tagEntries.map(([key, value]) => (
          <div key={key} className="flex flex-col">
            <span className="text-sm font-medium text-gray-700 dark:text-prowler-theme-pale/90">
              {key}:
            </span>
            <Snippet
              className="bg-gray-50 dark:bg-slate-800"
              hideSymbol
              size="sm"
              classNames={{
                base: "max-w-48",
              }}
            >
              <span className="text-xs">
                {renderValue(value).slice(0, 16)}
                {renderValue(value).length > 16 && "..."}
              </span>
            </Snippet>
          </div>
        ))}
      </div>
    </Section>
  );
};

const buildCustomBreadcrumbs = (
  resourceName: string,
  findingTitle?: string,
  onBackToResource?: () => void,
): CustomBreadcrumbItem[] => {
  const breadcrumbs: CustomBreadcrumbItem[] = [
    {
      name:
        resourceName.length > 20
          ? `${resourceName.slice(-20)}...`
          : resourceName,
      isClickable: !!findingTitle,
      onClick: findingTitle ? onBackToResource : undefined,
      isLast: !findingTitle,
    },
  ];

  if (findingTitle) {
    breadcrumbs.push({
      name: findingTitle,
      isLast: true,
      isClickable: false,
    });
  }

  return breadcrumbs;
};

export const ResourceDetail = ({
  resourceDetails,
}: {
  resourceDetails: ResourceProps;
}) => {
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    null,
  );
  const [findingDetails, setFindingDetails] = useState<FindingProps | null>(
    null,
  );

  const resource = resourceDetails;
  const attributes = resource.attributes;
  const providerData = resource.relationships.provider.data.attributes;
  const allFindings = resource.relationships.findings.data || [];

  const navigateToFinding = async (findingId: string) => {
    setSelectedFindingId(findingId);

    try {
      const findingData = await getFindingById(
        findingId,
        "resources,scan.provider",
      );
      if (findingData?.data) {
        // Create dictionaries for resources, scans, and providers
        const resourceDict = createDict("resources", findingData);
        const scanDict = createDict("scans", findingData);
        const providerDict = createDict("providers", findingData);

        // Expand the finding with its corresponding resource, scan, and provider
        const finding = findingData.data;
        const scan = scanDict[finding.relationships?.scan?.data?.id];
        const resource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        const provider = providerDict[scan?.relationships?.provider?.data?.id];

        const expandedFinding = {
          ...finding,
          relationships: { scan, resource, provider },
        };

        setFindingDetails(expandedFinding);
      }
    } catch (error) {
      console.error("Error fetching finding:", error);
    }
  };

  const handleBackToResource = () => {
    setSelectedFindingId(null);
    setFindingDetails(null);
  };

  // If a finding is selected, show the finding detail
  if (selectedFindingId) {
    const findingTitle =
      findingDetails?.attributes?.check_metadata?.checktitle ||
      "Finding Detail";

    return (
      <div className="flex flex-col gap-4">
        <BreadcrumbNavigation
          mode="custom"
          customItems={buildCustomBreadcrumbs(
            attributes.name,
            findingTitle,
            handleBackToResource,
          )}
        />

        {findingDetails && <FindingDetail findingDetails={findingDetails} />}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Resource Details section */}
      <Section title="Resource Details">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Resource ID" variant="simple">
            <Snippet className="bg-gray-50 py-1 dark:bg-slate-800" hideSymbol>
              <span className="whitespace-pre-line text-xs">
                {renderValue(attributes.uid)}
              </span>
            </Snippet>
          </InfoField>
          <div className="flex w-full items-end justify-between space-x-2">
            <EntityInfoShort
              cloudProvider={
                providerData.provider as "aws" | "azure" | "gcp" | "kubernetes"
              }
              entityAlias={providerData.alias as string}
              entityId={providerData.uid as string}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Resource Name">
            {renderValue(attributes.name)}
          </InfoField>
          <InfoField label="Resource Type">
            {renderValue(attributes.type)}
          </InfoField>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Service">
            {renderValue(attributes.service)}
          </InfoField>
          <InfoField label="Region">{renderValue(attributes.region)}</InfoField>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Created At">
            <DateWithTime inline dateTime={attributes.inserted_at} />
          </InfoField>
          <InfoField label="Last Updated">
            <DateWithTime inline dateTime={attributes.updated_at} />
          </InfoField>
        </div>
      </Section>

      {/* Resource Tags section */}
      <TagsSection tags={attributes.tags} />

      {/* Finding associated with this resource section */}
      <Section title="Findings associated with this resource">
        {allFindings.length > 0 ? (
          <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-prowler-theme-pale/80">
              Total findings: {allFindings.length}
            </p>
            {allFindings.map((finding: any, index: number) => {
              const { attributes: findingAttrs, id } = finding;

              // Handle cases where finding might not have all attributes
              if (!findingAttrs) {
                return (
                  <div
                    key={index}
                    className="flex flex-col gap-2 rounded-lg px-4 py-2 shadow-small dark:bg-prowler-blue-400"
                  >
                    <p className="text-sm text-red-600">
                      Finding {id} - No attributes available
                    </p>
                  </div>
                );
              }

              const { severity, check_metadata, status } = findingAttrs;
              const checktitle = check_metadata?.checktitle || "Unknown check";

              return (
                <button
                  key={index}
                  onClick={() => navigateToFinding(id)}
                  className="flex w-full cursor-pointer flex-col gap-2 rounded-lg px-4 py-2 shadow-small dark:bg-prowler-blue-400"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-medium text-gray-800 dark:text-prowler-theme-pale/90">
                      {checktitle}
                    </h3>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={severity || "-"} />
                      <StatusFindingBadge status={status || "-"} />
                      <InfoIcon
                        className="cursor-pointer text-primary"
                        size={16}
                        onClick={() => navigateToFinding(id)}
                      />
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        ) : (
          <p className="text-gray-600 dark:text-prowler-theme-pale/80">
            No findings found for this resource.
          </p>
        )}
      </Section>
    </div>
  );
};
