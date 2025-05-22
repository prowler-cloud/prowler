"use client";

import { Chip } from "@nextui-org/react";
import { useState } from "react";

import { CustomAlertModal, CustomButton } from "@/components/ui/custom";
import { DateWithTime } from "@/components/ui/entities";
import { MembershipDetailData } from "@/types/users/users";

import { EditTenantForm } from "./edit-tenant-form";

export const MembershipItem = ({
  membership,
  tenantName,
  tenantId,
}: {
  membership: MembershipDetailData;
  tenantName: string;
  tenantId: string;
}) => {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const isOwner = membership.attributes.role?.toLowerCase() === "owner";

  return (
    <>
      <CustomAlertModal
        isOpen={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Change organization name"
      >
        <EditTenantForm
          tenantId={tenantId}
          tenantName={tenantName}
          setIsOpen={setIsEditOpen}
        />
      </CustomAlertModal>

      <div className="min-w-[320px] rounded-lg bg-gray-50 p-2 dark:bg-gray-800">
        <div className="flex w-full flex-col space-y-2">
          <div className="flex items-center justify-between gap-2">
            <Chip size="sm" variant="flat" color="secondary">
              {membership.attributes.role}
            </Chip>
            {isOwner && (
              <CustomButton
                type="button"
                ariaLabel="Change name"
                className="text-blue-500"
                variant="flat"
                color="transparent"
                size="sm"
                onPress={() => setIsEditOpen(true)}
              >
                Change name
              </CustomButton>
            )}
          </div>
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-gray-500">
              <span className="text-xs">Name:</span>
              <p className="whitespace-nowrap text-xs font-semibold">
                {tenantName}
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-gray-500">
          <span className="">Joined on:</span>
          <DateWithTime inline dateTime={membership.attributes.date_joined} />
        </div>
      </div>
    </>
  );
};
