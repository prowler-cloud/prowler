"use client";

import { Snippet } from "@nextui-org/react";
import Link from "next/link";

import { SnippetId } from "@/components/ui/entities";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { SeverityBadge } from "@/components/ui/table/severity-badge";
import { FindingProps } from "@/types";

export const FindingDetail = ({
  findingDetails,
}: {
  findingDetails: FindingProps;
}) => {
  const finding = findingDetails;
  const attributes = finding.attributes;
  const resource = finding.relationships.resource.attributes;

  const remediation = attributes.check_metadata.remediation;

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="line-clamp-2 text-xl font-bold leading-tight text-gray-800 dark:text-prowler-theme-pale/90">
            {attributes.check_metadata.checktitle}
          </h2>
          <p className="text-sm text-gray-500 dark:text-prowler-theme-pale/70">
            {resource.service}
          </p>
        </div>
        <div
          className={`rounded-lg px-3 py-1 text-sm font-semibold ${
            attributes.status === "PASS"
              ? "bg-green-100 text-green-600"
              : attributes.status === "MANUAL"
                ? "bg-gray-100 text-gray-600"
                : "bg-red-100 text-red-600"
          }`}
        >
          {attributes.status}
        </div>
      </div>

      {/* Check Metadata */}
      <div className="flex flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold text-gray-800 dark:text-prowler-theme-pale/90">
            Finding details
          </h3>
          <SeverityBadge severity={attributes.severity} />
        </div>
        {attributes.status === "FAIL" && (
          <Snippet
            className="max-w-full py-4"
            color="danger"
            hideCopyButton
            hideSymbol
          >
            <p className="text-sm font-semibold dark:text-prowler-theme-pale">
              Risk
            </p>
            <p className="whitespace-pre-line text-gray-800 dark:text-prowler-theme-pale/90">
              {attributes.check_metadata.risk}
            </p>
          </Snippet>
        )}

        <div className="flex flex-col gap-2">
          <p className="text-sm font-semibold dark:text-prowler-theme-pale">
            Description
          </p>
          <p className="text-gray-800 dark:text-prowler-theme-pale/90">
            {attributes.check_metadata.description}
          </p>
        </div>

        <div className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold dark:text-prowler-theme-pale">
            Remediation
          </h3>
          <div className="text-gray-800 dark:text-prowler-theme-pale/90">
            {remediation.recommendation && (
              <>
                <p className="text-sm font-semibold">Recommendation:</p>
                <p>{remediation.recommendation.text}</p>
                <Link
                  target="_blank"
                  href={remediation.recommendation.url}
                  className="mt-2 inline-block text-sm text-blue-500 underline"
                >
                  Learn more
                </Link>
              </>
            )}
            {remediation.code &&
              Object.values(remediation.code).some(Boolean) && (
                <div className="flex flex-col gap-2">
                  <p className="mt-4 text-sm font-semibold">
                    Reference Information:
                  </p>
                  <div className="flex flex-col gap-2">
                    {remediation.code.cli && (
                      <div>
                        <p className="text-sm font-semibold">CLI Command:</p>
                        <Snippet hideSymbol size="sm" className="max-w-full">
                          <p className="whitespace-pre-line">
                            {remediation.code.cli}
                          </p>
                        </Snippet>
                      </div>
                    )}
                    <div className="flex flex-row gap-4">
                      {Object.entries(remediation.code)
                        .filter(([key]) => key !== "cli")
                        .map(([key, value]) =>
                          value ? (
                            <Link
                              key={key}
                              href={value}
                              target="_blank"
                              className="text-sm font-medium text-blue-500"
                            >
                              {key === "other"
                                ? "External doc"
                                : key.charAt(0).toUpperCase() +
                                  key.slice(1).toLowerCase()}
                            </Link>
                          ) : null,
                        )}
                    </div>
                  </div>
                </div>
              )}
          </div>
        </div>
      </div>

      {/* Resources Section */}
      <div className="flex flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
        <h3 className="text-lg font-bold text-gray-800 dark:text-prowler-theme-pale/90">
          Resource Details
        </h3>
        <div className="grid grid-cols-2 gap-6">
          <div className="col-span-2">
            <p className="text-sm font-semibold dark:text-prowler-theme-pale">
              Resource ID
            </p>
            <Snippet size="sm" hideSymbol className="max-w-full">
              <p className="whitespace-pre-line">{resource.uid}</p>
            </Snippet>
          </div>
          <div>
            <p className="text-sm font-semibold dark:text-prowler-theme-pale">
              Resource Name
            </p>
            <p className="text-gray-800 dark:text-prowler-theme-pale/90">
              {resource.name}
            </p>
          </div>
          <div>
            <p className="text-sm font-semibold dark:text-prowler-theme-pale">
              Region
            </p>
            <p className="text-gray-800 dark:text-prowler-theme-pale/90">
              {resource.region}
            </p>
          </div>
          <div>
            <p className="text-sm font-semibold dark:text-prowler-theme-pale">
              Resource Type
            </p>
            <p className="text-gray-800 dark:text-prowler-theme-pale/90">
              {resource.type}
            </p>
          </div>
          <div>
            <p className="text-sm font-semibold dark:text-prowler-theme-pale">
              Severity
            </p>
            <SeverityBadge severity={attributes.severity} />
          </div>
          {resource.tags &&
            Object.entries(resource.tags).map(([key, value]) => (
              <div key={key}>
                <p className="text-sm font-semibold dark:text-prowler-theme-pale">
                  Tag: {key}
                </p>
                <SnippetId
                  entityId={value}
                  hideSymbol
                  size="sm"
                  className="max-w-full"
                >
                  <p className="whitespace-pre-line">{value}</p>
                </SnippetId>
              </div>
            ))}
          <div className="col-span-2 grid grid-cols-2 gap-6">
            <div>
              <p className="text-sm font-semibold dark:text-prowler-theme-pale">
                First seen
              </p>
              <DateWithTime inline dateTime={resource.inserted_at} />
            </div>
            <div>
              <p className="text-sm font-semibold dark:text-prowler-theme-pale">
                Last seen
              </p>
              <DateWithTime inline dateTime={resource.updated_at} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
