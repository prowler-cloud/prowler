"use client";

import { Snippet } from "@heroui/snippet";
import { Spinner } from "@heroui/spinner";
import { Tooltip } from "@heroui/tooltip";
import { ExternalLink, InfoIcon } from "lucide-react";
import { useEffect, useState } from "react";

import { getFindingById } from "@/actions/findings";
import { getResourceById } from "@/actions/resources";
import { FindingDetail } from "@/components/findings/table/finding-detail";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { BreadcrumbNavigation, CustomBreadcrumbItem } from "@/components/ui";
import {
  DateWithTime,
  getProviderLogo,
  InfoField,
} from "@/components/ui/entities";
import { SeverityBadge, StatusFindingBadge } from "@/components/ui/table";
import { createDict } from "@/lib";
import { buildGitFileUrl } from "@/lib/iac-utils";
import { FindingProps, ProviderType, ResourceProps } from "@/types";

const renderValue = (value: string | null | undefined) => {
  return value && value.trim() !== "" ? value : "-";
};

const buildCustomBreadcrumbs = (
  _resourceName: string,
  findingTitle?: string,
  onBackToResource?: () => void,
): CustomBreadcrumbItem[] => {
  const breadcrumbs: CustomBreadcrumbItem[] = [
    {
      name: "Resource Details",
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
  resourceId,
  initialResourceData,
}: {
  resourceId: string;
  initialResourceData: ResourceProps;
}) => {
  const [findingsData, setFindingsData] = useState<any[]>([]);
  const [resourceTags, setResourceTags] = useState<Record<string, string>>({});
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    null,
  );
  const [findingDetails, setFindingDetails] = useState<FindingProps | null>(
    null,
  );

  useEffect(() => {
    const loadFindings = async () => {
      setFindingsLoading(true);

      try {
        const resourceData = await getResourceById(resourceId, {
          include: ["findings"],
          fields: ["tags", "findings"],
        });

        if (resourceData?.data) {
          // Get tags from the detailed resource data
          setResourceTags(resourceData.data.attributes.tags || {});

          // Create dictionary for findings and expand them
          if (resourceData.data.relationships?.findings) {
            const findingsDict = createDict("findings", resourceData);
            const findings =
              resourceData.data.relationships.findings.data?.map(
                (finding: any) => findingsDict[finding.id],
              ) || [];
            setFindingsData(findings);
          } else {
            setFindingsData([]);
          }
        } else {
          setFindingsData([]);
          setResourceTags({});
        }
      } catch (err) {
        console.error("Error loading findings:", err);
        setFindingsData([]);
        setResourceTags({});
      } finally {
        setFindingsLoading(false);
      }
    };

    if (resourceId) {
      loadFindings();
    }
  }, [resourceId]);

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

  if (!initialResourceData) {
    return (
      <div className="flex min-h-96 flex-col items-center justify-center gap-4 rounded-lg p-8">
        <Spinner size="lg" />
        <p className="dark:text-prowler-theme-pale/80 text-sm text-gray-600">
          Loading resource details...
        </p>
      </div>
    );
  }

  const resource = initialResourceData;
  const attributes = resource.attributes;
  const providerData = resource.relationships.provider.data.attributes;
  const allFindings = findingsData;

  // Build Git URL for IaC resources
  const gitUrl =
    providerData.provider === "iac"
      ? buildGitFileUrl(
          providerData.uid,
          attributes.name,
          "",
          attributes.region,
        )
      : null;

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
      <Card variant="base" padding="lg">
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div className="flex flex-row items-center justify-start gap-2">
            <CardTitle>Resource Details</CardTitle>
            {providerData.provider === "iac" && gitUrl && (
              <Tooltip content="Go to Resource in the Repository" size="sm">
                <a
                  href={gitUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-bg-data-info mt-1 inline-flex cursor-pointer"
                  aria-label="Open resource in repository"
                >
                  <ExternalLink size={16} className="inline" />
                </a>
              </Tooltip>
            )}
          </div>
          {getProviderLogo(providerData.provider as ProviderType)}
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <InfoField label="Resource UID" variant="simple">
            <Snippet
              className="border-border-neutral-tertiary bg-bg-neutral-tertiary rounded-lg border py-1"
              hideSymbol
            >
              <span className="text-xs whitespace-pre-line">
                {renderValue(attributes.uid)}
              </span>
            </Snippet>
          </InfoField>

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
            <InfoField label="Region">
              {renderValue(attributes.region)}
            </InfoField>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoField label="Created At">
              <DateWithTime inline dateTime={attributes.inserted_at} />
            </InfoField>
            <InfoField label="Last Updated">
              <DateWithTime inline dateTime={attributes.updated_at} />
            </InfoField>
          </div>

          {resourceTags && Object.entries(resourceTags).length > 0 ? (
            <div className="flex flex-col gap-4">
              <h4 className="text-sm font-bold text-gray-500 dark:text-gray-400">
                Tags
              </h4>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                {Object.entries(resourceTags).map(([key, value]) => (
                  <InfoField key={key} label={key}>
                    {renderValue(value)}
                  </InfoField>
                ))}
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Finding associated with this resource section */}
      <Card variant="base" padding="lg">
        <CardHeader>
          <CardTitle>Findings associated with this resource</CardTitle>
        </CardHeader>
        <CardContent>
          {findingsLoading ? (
            <div className="flex items-center justify-center gap-2 py-8">
              <Spinner size="sm" />
              <p className="dark:text-prowler-theme-pale/80 text-sm text-gray-600">
                Loading findings...
              </p>
            </div>
          ) : allFindings.length > 0 ? (
            <div className="flex flex-col gap-4">
              <p className="dark:text-prowler-theme-pale/80 text-sm text-gray-600">
                Total findings: {allFindings.length}
              </p>
              {allFindings.map((finding: any, index: number) => {
                const { attributes: findingAttrs, id } = finding;

                // Handle cases where finding might not have all attributes
                if (!findingAttrs) {
                  return (
                    <div
                      key={index}
                      className="shadow-small dark:bg-prowler-blue-400 flex flex-col gap-2 rounded-lg px-4 py-2"
                    >
                      <p className="text-sm text-red-600">
                        Finding {id} - No attributes available
                      </p>
                    </div>
                  );
                }

                const { severity, check_metadata, status } = findingAttrs;
                const checktitle =
                  check_metadata?.checktitle || "Unknown check";

                return (
                  <button
                    key={index}
                    onClick={() => navigateToFinding(id)}
                    className="shadow-small border-border-neutral-tertiary bg-bg-neutral-tertiary flex w-full cursor-pointer flex-col gap-2 rounded-lg px-4 py-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="dark:text-prowler-theme-pale/90 text-left text-sm font-medium text-gray-800">
                        {checktitle}
                      </h3>
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={severity || "-"} />
                        <StatusFindingBadge status={status || "-"} />
                        <InfoIcon
                          className="text-button-primary cursor-pointer"
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
            <p className="dark:text-prowler-theme-pale/80 text-gray-600">
              No findings found for this resource.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
