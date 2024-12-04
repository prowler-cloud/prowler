"use client";

import { Card, CardBody } from "@nextui-org/react";

import { AddIcon } from "@/components/icons/Icons";
import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
} from "@/components/icons/providers-badge";
import { CustomButton } from "@/components/ui/custom/custom-button";
import { ProviderOverviewProps } from "@/types";

export const ProvidersOverview = ({
  providersOverview,
}: {
  providersOverview: ProviderOverviewProps;
}) => {
  const calculatePassingPercentage = (pass: number, total: number) =>
    total > 0 ? ((pass / total) * 100).toFixed(2) : "0.00";

  const renderProviderBadge = (providerId: string) => {
    switch (providerId) {
      case "aws":
        return <AWSProviderBadge width={30} height={30} />;
      case "azure":
        return <AzureProviderBadge width={30} height={30} />;
      case "gcp":
        return <GCPProviderBadge width={30} height={30} />;
      case "kubernetes":
        return <KS8ProviderBadge width={30} height={30} />;
      default:
        return null;
    }
  };

  const providers = [
    { id: "aws", name: "AWS" },
    { id: "azure", name: "Azure" },
    { id: "gcp", name: "GCP" },
    { id: "kubernetes", name: "Kubernetes" },
  ];

  if (!providersOverview || !Array.isArray(providersOverview.data)) {
    return (
      <Card className="h-full dark:bg-prowler-blue-400">
        <CardBody>
          <div className="my-auto grid grid-cols-1 gap-3">
            <div className="grid grid-cols-4 border-b pb-2 text-xs font-semibold">
              <span className="text-center">Provider</span>
              <span className="flex flex-col items-center text-center">
                <span>Percent</span>
                <span>Passing</span>
              </span>
              <span className="flex flex-col items-center text-center">
                <span>Failing</span>
                <span>Checks</span>
              </span>
              <span className="flex flex-col items-center text-center">
                <span>Total</span>
                <span>Resources</span>
              </span>
            </div>

            {providers.map((providerTemplate) => (
              <div
                key={providerTemplate.id}
                className="grid grid-cols-4 items-center border-b py-2 text-sm"
              >
                <span className="flex items-center justify-center px-4">
                  {renderProviderBadge(providerTemplate.id)}
                </span>
                <span className="text-center">0.00%</span>
                <span className="text-center">-</span>
                <span className="text-center">-</span>
              </div>
            ))}

            <div className="grid grid-cols-4 items-center border-b py-2 text-sm font-semibold">
              <span className="flex items-center justify-center px-4">
                Total
              </span>
              <span className="text-center">0.00%</span>
              <span className="text-center">-</span>
              <span className="text-center">-</span>
            </div>
          </div>
        </CardBody>
      </Card>
    );
  }

  return (
    <Card className="h-full dark:bg-prowler-blue-400">
      <CardBody>
        <div className="my-auto grid grid-cols-1 gap-3">
          <div className="grid grid-cols-4 border-b pb-2 text-xs font-semibold">
            <span className="text-center">Provider</span>
            <span className="flex flex-col items-center text-center">
              <span>Percent</span>
              <span>Passing</span>
            </span>
            <span className="flex flex-col items-center text-center">
              <span>Failing</span>
              <span>Checks</span>
            </span>
            <span className="flex flex-col items-center text-center">
              <span>Total</span>
              <span>Resources</span>
            </span>
          </div>

          {providers.map((providerTemplate) => {
            const providerData = providersOverview.data.find(
              (p) => p.id === providerTemplate.id,
            );

            return (
              <div
                key={providerTemplate.id}
                className="grid grid-cols-4 items-center border-b py-2 text-sm"
              >
                <span className="flex items-center justify-center px-4">
                  {renderProviderBadge(providerTemplate.id)}
                </span>
                <span className="text-center">
                  {providerData
                    ? calculatePassingPercentage(
                        providerData.attributes.findings.pass,
                        providerData.attributes.findings.total,
                      )
                    : "0.00"}
                  %
                </span>
                <span className="text-center">
                  {providerData ? providerData.attributes.findings.fail : "-"}
                </span>
                <span className="text-center">
                  {providerData ? providerData.attributes.resources.total : "-"}
                </span>
              </div>
            );
          })}

          {/* Totals row */}
          <div className="grid grid-cols-4 items-center border-b py-2 text-sm font-semibold">
            <span className="flex items-center justify-center px-4">Total</span>
            <span className="text-center">
              {calculatePassingPercentage(
                providersOverview.data.reduce(
                  (sum, provider) => sum + provider.attributes.findings.pass,
                  0,
                ),
                providersOverview.data.reduce(
                  (sum, provider) => sum + provider.attributes.findings.total,
                  0,
                ),
              )}
              %
            </span>
            <span className="text-center">
              {providersOverview.data.reduce(
                (sum, provider) => sum + provider.attributes.findings.fail,
                0,
              )}
            </span>
            <span className="text-center">
              {providersOverview.data.reduce(
                (sum, provider) => sum + provider.attributes.resources.total,
                0,
              )}
            </span>
          </div>
        </div>
        <div className="mt-4 flex w-full items-center justify-end">
          <CustomButton
            asLink="/providers"
            ariaLabel="Go to Providers page"
            variant="solid"
            color="action"
            size="sm"
            endContent={<AddIcon size={20} />}
          >
            Add Provider
          </CustomButton>
        </div>
      </CardBody>
    </Card>
  );
};
