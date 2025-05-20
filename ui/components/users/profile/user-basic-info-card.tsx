"use client";

import { Card, CardBody, Divider, Tooltip } from "@nextui-org/react";
import { CircleUserRound } from "lucide-react";
import { useState } from "react";

import { CopyIcon, DoneIcon } from "@/components/icons";
import { CustomButton } from "@/components/ui/custom/custom-button";
import { DateWithTime } from "@/components/ui/entities";
import { UserDataWithRoles } from "@/types/users/users";

const TenantIdCopy = ({ id }: { id: string }) => {
  const [copied, setCopied] = useState(false);

  const handleCopyTenantId = () => {
    navigator.clipboard.writeText(id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex items-center justify-between">
      <p className="text-sm font-semibold text-default-600">Tenant ID:</p>
      <div className="flex items-center">
        <Tooltip content={copied ? "Copied!" : "Copy ID"}>
          <CustomButton
            ariaLabel="Copy Tenant ID"
            onPress={handleCopyTenantId}
            variant="light"
            color="primary"
            size="sm"
          >
            <span className="mr-2 max-w-[120px] overflow-hidden overflow-ellipsis whitespace-nowrap">
              {id}
            </span>
            {copied ? (
              <DoneIcon size={16} className="text-success" />
            ) : (
              <CopyIcon size={16} />
            )}
          </CustomButton>
        </Tooltip>
      </div>
    </div>
  );
};

export const UserBasicInfoCard = ({ user }: { user: UserDataWithRoles }) => {
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
          <TenantIdCopy id={user.id} />
        </div>
      </CardBody>
    </Card>
  );
};
