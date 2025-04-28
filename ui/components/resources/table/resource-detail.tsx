import { Snippet } from "@nextui-org/react";
import { format, parseISO } from "date-fns";
import { InfoIcon } from "lucide-react";
import { useRouter } from "next/navigation";

import {
  DateWithTime,
  getProviderLogo,
  InfoField,
  ProviderType,
} from "@/components/ui/entities";
import { SeverityBadge, StatusFindingBadge } from "@/components/ui/table";
import { ResourceApiResponse, ResourceProps } from "@/types";
import { SkeletonFindingSummary } from "../skeleton/skeleton-finding-summary";

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

export const ResourceDetail = ({
  resourceDetails,
  resourceData,
  isLoading,
}: {
  resourceDetails: ResourceApiResponse | null;
  resourceData: ResourceProps;
  isLoading: boolean;
}) => {
  const router = useRouter();

  const failedFindings = resourceDetails?.included.filter(
    (item) =>
      item.type === "findings" &&
      item.attributes?.status === "FAIL" &&
      item.attributes?.delta === "new",
  );

  const linkToFindingsFromResources = (
    uid: string,
    inserted_at: string,
    resourceId: string,
  ) => {
    const formattedDate = format(parseISO(inserted_at), "yyyy-MM-dd");
    router.push(
      `/findings?filter[uid]=${uid}&filter[inserted_at]=${formattedDate}&id=${resourceId}`,
    );
  };

  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Resource Details section */}
      <Section title="Resource Details">
        <InfoField label="Resource ID" variant="simple">
          <Snippet className="bg-gray-50 py-1 dark:bg-slate-800" hideSymbol>
            <span className="whitespace-pre-line text-xs">
              {renderValue(resourceData?.attributes.uid)}
            </span>
          </Snippet>
        </InfoField>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Resource Name">
            {renderValue(resourceData.attributes.name)}
          </InfoField>
          <InfoField label="Resource Type">
            {renderValue(resourceData.attributes.type)}
          </InfoField>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Service">
            {renderValue(resourceData.attributes.service)}
          </InfoField>
          <InfoField label="Region">
            {renderValue(resourceData.attributes.region)}
          </InfoField>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Created At">
            <DateWithTime
              inline
              dateTime={resourceData.attributes.inserted_at}
            />
          </InfoField>
          <InfoField label="Last Updated">
            <DateWithTime
              inline
              dateTime={resourceData.attributes.updated_at}
            />
          </InfoField>
        </div>
      </Section>

      {/* Provider Details section */}
      <Section title="Provider Details">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {resourceData.relationships.provider.data.attributes.alias && (
            <InfoField label="Alias">
              {resourceData.relationships.provider.data.attributes.alias}
            </InfoField>
          )}
          <InfoField label="Account ID">
            {resourceData.relationships.provider.data.attributes.uid}
          </InfoField>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <InfoField label="Provider" variant="simple">
            {getProviderLogo(
              resourceData.relationships.provider.data.attributes
                .provider as ProviderType,
            )}
          </InfoField>
        </div>
      </Section>

      {/* Finding Details section */}
      <div>
        <h2 className="line-clamp-2 text-lg font-medium leading-tight text-gray-800 dark:text-prowler-theme-pale/90">
          Findings Details
        </h2>
      </div>
      {isLoading ? (
        <SkeletonFindingSummary />
      ) : failedFindings && failedFindings?.length > 0 ? (
        failedFindings.map((finding, index) => {
          const { attributes, id } = finding;
          const { severity, uid, inserted_at, check_metadata, status } =
            attributes;

          const { checktitle } = check_metadata;

          return (
            <div
              key={index}
              className="flex flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400"
            >
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h3 className="text-md font-medium text-gray-800 dark:text-prowler-theme-pale/90">
                    {checktitle}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={severity || "-"} />
                  <StatusFindingBadge status={status || "-"} />
                  <InfoIcon
                    className="cursor-pointer text-primary"
                    size={16}
                    onClick={() =>
                      linkToFindingsFromResources(uid, inserted_at, id)
                    }
                  />
                </div>
              </div>
            </div>
          );
        })
      ) : (
        <p className="text-gray-600 dark:text-prowler-theme-pale/80">
          No data found.
        </p>
      )}
    </div>
  );
};
