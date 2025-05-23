"use client";

import { Card, CardBody, Divider } from "@nextui-org/react";

import { DateWithTime, SnippetChip } from "@/components/ui/entities";
import { UserDataWithRoles } from "@/types/users/users";

import { ProwlerShort } from "../../icons";

const TenantIdCopy = ({ id }: { id: string }) => {
  return (
    <div className="flex items-center gap-2 whitespace-nowrap md:flex-col md:items-start md:justify-start">
      <p className="text-sm font-semibold text-default-600">
        Active organization ID:
      </p>
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
        <div className="flex h-10 w-10 items-center justify-center rounded-full border-3 border-black p-1 dark:border-white">
          <ProwlerShort />
        </div>
        <Divider className="my-4" />
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-start md:gap-8">
          <div className="flex gap-2 whitespace-nowrap md:flex-col md:items-start md:justify-start">
            <p className="text-sm font-semibold text-default-600">Name:</p>
            <span className="text-sm">{name}</span>
          </div>
          <div className="flex gap-2 whitespace-nowrap md:flex-col md:items-start md:justify-start">
            <p className="text-sm font-semibold text-default-600">Email:</p>
            <span className="text-sm">{email}</span>
          </div>
          <div className="flex gap-2 whitespace-nowrap md:flex-col md:items-start md:justify-start">
            <p className="text-sm font-semibold text-default-600">
              Date Joined:
            </p>
            <span className="text-sm">
              <DateWithTime inline dateTime={date_joined} />
            </span>
          </div>
          <TenantIdCopy id={tenantId} />
          <div className="flex gap-2 whitespace-nowrap md:flex-col md:items-start md:justify-start">
            <p className="text-sm font-semibold text-default-600">Company:</p>
            <span className="text-sm">{company_name}</span>
          </div>
        </div>
      </CardBody>
    </Card>
  );
};
