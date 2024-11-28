"use client";

import { Card, CardBody } from "@nextui-org/react";

import { DateWithTime } from "@/components/ui/entities";
import { UserProfileProps } from "@/types";

export const UserInfo = ({ user }: { user: UserProfileProps["data"] }) => {
  const { name, email, company_name, date_joined } = user.attributes;

  return (
    <Card className="dark:bg-prowler-blue-400">
      <CardBody>
        <div className="space-y-3">
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
        </div>
      </CardBody>
    </Card>
  );
};
