"use client";

import { Card, CardBody, CardHeader } from "@nextui-org/react";

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
  console.log(providersOverview);
  if (!providersOverview || !Array.isArray(providersOverview.data)) {
    return <p>No provider data available</p>;
  }

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

  return (
    <Card className="dark:bg-prowler-blue-400">
      <CardHeader>
        <h3 className="text-sm font-bold">Providers Overview</h3>
      </CardHeader>
      <CardBody>
        <div className="grid grid-cols-1 gap-3">
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

          {providersOverview.data.length === 0 ? (
            <div className="grid grid-cols-4 items-center border-b py-2 text-sm">
              <span className="flex items-center justify-center px-4">-</span>
              <span className="text-center">-</span>
              <span className="text-center">-</span>
              <span className="text-center">-</span>
            </div>
          ) : (
            providersOverview.data.map((provider) => {
              const { pass, fail, total } = provider.attributes.findings;
              const resourcesTotal = provider.attributes.resources.total;

              return (
                <div
                  key={provider.id}
                  className="grid grid-cols-4 items-center border-b py-2 text-sm"
                >
                  <span className="flex items-center justify-center px-4">
                    {renderProviderBadge(provider.id)}
                  </span>
                  <span className="text-center">
                    {calculatePassingPercentage(pass, total)}%
                  </span>
                  <span className="text-center">{fail}</span>
                  <span className="text-center">{resourcesTotal}</span>
                </div>
              );
            })
          )}
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
            Go to Providers
          </CustomButton>
        </div>
      </CardBody>
    </Card>
  );
};
