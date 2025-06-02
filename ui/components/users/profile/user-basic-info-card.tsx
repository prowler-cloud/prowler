"use client";

import { Card, CardBody, Divider } from "@nextui-org/react";

import { DateWithTime, InfoField, SnippetChip } from "@/components/ui/entities";
import { UserDataWithRoles } from "@/types/users";

import { ProwlerShort } from "../../icons";

const TenantIdCopy = ({ id }: { id: string }) => {
  return (
    <div className="flex items-center gap-2 whitespace-nowrap md:flex-col md:items-start md:justify-start">
      <SnippetChip value={id} />
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
    <Card className="dark:bg-prowler-blue-400">
      <CardBody>
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
          <div className="flex flex-col gap-2">
            <InfoField label="Organization ID" variant="transparent">
              <TenantIdCopy id={tenantId} />
            </InfoField>
          </div>
        </div>
      </CardBody>
    </Card>
  );
};
