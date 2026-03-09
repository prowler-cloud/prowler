"use client";

import { Divider } from "@heroui/divider";

import { ProwlerShort } from "@/components/icons";
import { Card, CardContent } from "@/components/shadcn";
import { DateWithTime, InfoField, SnippetChip } from "@/components/ui/entities";
import { UserDataWithRoles } from "@/types/users";

const TenantIdCopy = ({ id }: { id: string }) => {
  return (
    <div className="flex max-w-full min-w-0 items-center gap-2 md:flex-col md:items-start md:justify-start">
      <SnippetChip value={id} className="max-w-full" />
    </div>
  );
};

export const UserBasicInfoCard = ({
  user,
  tenantId,
}: {
  user: UserDataWithRoles;
  tenantId: string;
}) => {
  const { name, email, company_name, date_joined } = user.attributes;

  return (
    <Card variant="base" padding="none" className="p-4">
      <CardContent>
        <div className="flex items-center gap-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-full border-3 border-black p-1 dark:border-white">
            <ProwlerShort />
          </div>
          <div className="flex flex-col">
            <span className="text-md font-bold">{name}</span>
            <span className="text-xs font-light">
              {email}
              {company_name && ` | ${company_name}`}
            </span>
          </div>
        </div>
        <Divider className="my-4" />
        <div className="flex flex-row gap-4 md:items-start md:justify-start md:gap-8">
          <div className="flex gap-2 whitespace-nowrap md:flex-col md:items-start md:justify-start">
            <div className="flex items-center gap-2">
              <InfoField label="Date Joined" variant="simple">
                <DateWithTime inline dateTime={date_joined} />
              </InfoField>
            </div>
          </div>
          <div className="flex min-w-0 flex-1 flex-col gap-2 overflow-hidden">
            <InfoField label="Organization ID" variant="transparent">
              {tenantId ? (
                <TenantIdCopy id={tenantId} />
              ) : (
                <span className="text-xs font-light">No organization</span>
              )}
            </InfoField>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
