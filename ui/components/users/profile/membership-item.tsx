"use client";

import { Chip } from "@heroui/chip";
import { useState } from "react";

import { Button, Card } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
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
      <Modal open={isEditOpen} onOpenChange={setIsEditOpen} title="">
        <EditTenantForm
          tenantId={tenantId}
          tenantName={tenantName}
          setIsOpen={setIsEditOpen}
        />
      </Modal>
      <Card variant="inner" className="min-w-[320px] p-2">
        <div className="flex w-full items-center gap-4">
          <Chip size="sm" variant="flat" color="secondary">
            {membership.attributes.role}
          </Chip>

          <div className="flex flex-row flex-wrap gap-1 gap-x-4">
            <InfoField label="Name" inline variant="transparent">
              <span className="font-semibold whitespace-nowrap">
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
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setIsEditOpen(true)}
              className="ml-auto"
            >
              Edit
            </Button>
          )}
        </div>
      </Card>
    </>
  );
};
