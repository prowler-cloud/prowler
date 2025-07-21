"use client";

import { Card, CardBody, CardHeader, Chip } from "@nextui-org/react";
import { SettingsIcon } from "lucide-react";
import Link from "next/link";

import { AmazonS3Icon } from "@/components/icons/services/IconServices";
import { CustomButton } from "@/components/ui/custom";
import { IntegrationProps } from "@/types/integrations";

interface S3IntegrationCardProps {
  integrations?: IntegrationProps[];
}

export const S3IntegrationCard = ({
  integrations = [],
}: S3IntegrationCardProps) => {
  const s3Integrations = integrations.filter(
    (integration) => integration.attributes.integration_type === "amazon_s3",
  );

  const isConfigured = s3Integrations.length > 0;
  const connectedCount = s3Integrations.filter(
    (integration) => integration.attributes.connected,
  ).length;

  return (
    <Card className="dark:bg-prowler-blue-400">
      <CardHeader className="gap-2">
        <div className="flex w-full items-center justify-between">
          <div className="flex items-center gap-3">
            <AmazonS3Icon size={40} />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold">Amazon S3</h4>
              <div className="flex items-center gap-2">
                <p className="text-xs text-gray-500">
                  Export security findings to Amazon S3 buckets.
                </p>
                {/* Todo: add real DOCS, use CustomLink when available */}
                <Link
                  href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-primary"
                  aria-label="Learn more about S3 integration"
                >
                  Learn more
                </Link>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isConfigured && (
              <Chip
                size="sm"
                color={connectedCount > 0 ? "success" : "warning"}
                variant="flat"
              >
                {connectedCount} / {s3Integrations.length} connected
              </Chip>
            )}
            <CustomButton
              size="sm"
              variant="bordered"
              startContent={<SettingsIcon size={14} />}
              asLink="/integrations/s3"
              ariaLabel={
                isConfigured
                  ? "Manage S3 integrations"
                  : "Configure S3 integration"
              }
            >
              {isConfigured ? "Manage" : "Configure"}
            </CustomButton>
          </div>
        </div>
      </CardHeader>
      <CardBody>
        <div className="flex flex-col gap-4">
          {isConfigured ? (
            <>
              <div className="text-sm">
                <span className="font-medium">Status: </span>
                <span
                  className={
                    connectedCount > 0 ? "text-prowler-green" : "text-warning"
                  }
                >
                  {connectedCount > 0 ? "Active" : "Configuration Required"}
                </span>
              </div>

              <div className="space-y-2">
                {s3Integrations.map((integration) => (
                  <div
                    key={integration.id}
                    className="flex items-center justify-between rounded-lg border p-3"
                  >
                    <div className="flex flex-col">
                      <span className="text-sm font-medium">
                        {integration.attributes.configuration.bucket_name ||
                          "Unknown Bucket"}
                      </span>
                      <span className="text-xs text-gray-500">
                        Path: {integration.attributes.configuration.path || "/"}
                      </span>
                    </div>
                    <Chip
                      size="sm"
                      color={
                        integration.attributes.connected ? "success" : "danger"
                      }
                      variant="dot"
                    >
                      {integration.attributes.connected
                        ? "Connected"
                        : "Disconnected"}
                    </Chip>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <>
              <div className="text-sm">
                <span className="font-medium">Status: </span>
                <span className="text-gray-500">Not Configured</span>
              </div>

              <div className="space-y-3">
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  Export your security findings to Amazon S3 buckets
                  automatically.
                </p>
              </div>
            </>
          )}
        </div>
      </CardBody>
    </Card>
  );
};
