"use client";

import { Card, CardBody, Divider } from "@nextui-org/react";
import { CircleUserRound } from "lucide-react";

import { DateWithTime, SnippetChip } from "@/components/ui/entities";
import { UserDataWithRoles } from "@/types/users/users";

const TenantIdCopy = ({ id }: { id: string }) => {
  return (
    <div className="flex items-center justify-between">
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
        <div className="space-y-3">
          <CircleUserRound className="h-8 w-8" />
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-default-600">Name:</p>
            <span className="text-sm">{name}</span>
          </div>
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-default-600">Email:</p>
            <span className="text-sm">{email}</span>
          </div>
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-default-600">Company:</p>
            <span className="text-sm">{company_name}</span>
          </div>
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-default-600">
              Date Joined:
            </p>
            <span className="text-sm">
              <DateWithTime inline dateTime={date_joined} />
            </span>
          </div>
          <Divider className="my-2" />
          <TenantIdCopy id={tenantId} />
        </div>
      </CardBody>
    </Card>
  );
};
