"use client";

import { Chip } from "@nextui-org/react";
import { useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";
import { DateWithTime, InfoField } from "@/components/ui/entities";
import { MembershipDetailData } from "@/types/users";

import { EditTenantForm } from "../forms";

export const MembershipItem = ({
  membership,
  tenantName,
  tenantId,
  isOwner,
}: {
  membership: MembershipDetailData;
  tenantName: string;
  tenantId: string;
  isOwner: boolean;
}) => {
  const [isEditOpen, setIsEditOpen] = useState(false);

  return (
    <>
      <CustomAlertModal
        isOpen={isEditOpen}
        onOpenChange={setIsEditOpen}
        title=""
      >
        <EditTenantForm
          tenantId={tenantId}
          tenantName={tenantName}
          setIsOpen={setIsEditOpen}
        />
      </CustomAlertModal>

      <div className="min-w-[320px] rounded-lg bg-gray-50 p-2 dark:bg-gray-800">
        <div className="flex w-full items-center gap-4">
          <Chip size="sm" variant="flat" color="secondary">
            {membership.attributes.role}
          </Chip>

          <div className="flex flex-col gap-1 md:flex-row md:gap-x-4">
            <InfoField label="Name" inline variant="transparent">
              <span className="whitespace-nowrap font-semibold">
                {tenantName}
              </span>
            </InfoField>
            <InfoField label="Joined on" inline variant="transparent">
              <DateWithTime
                inline
                showTime={false}
                dateTime={membership.attributes.date_joined}
              />
            </InfoField>
          </div>

          {isOwner && (
            <CustomButton
              type="button"
              ariaLabel="Change name"
              className="ml-auto text-blue-500"
              variant="flat"
              color="transparent"
              size="sm"
              onPress={() => setIsEditOpen(true)}
            >
              Change name
            </CustomButton>
          )}
        </div>
      </div>
    </>
  );
};
