"use client";

import { useState } from "react";

import { Badge, Button, Card } from "@/components/shadcn";
import { AlertModal } from "@/components/shadcn/alert-modal/alert-modal";
import { Modal } from "@/components/shadcn/modal";
import { DateWithTime, InfoField } from "@/components/ui/entities";
import { EditTenantForm } from "@/components/users/forms";
import { DeleteTenantForm } from "@/components/users/forms/delete-tenant-form";
import { SwitchTenantForm } from "@/components/users/forms/switch-tenant-form";
import { MembershipDetailData } from "@/types/users";

export const MembershipItem = ({
  membership,
  tenantName,
  tenantId,
  isOwner,
  sessionTenantId,
  availableTenants,
  membershipCount,
}: {
  membership: MembershipDetailData;
  tenantName: string;
  tenantId: string;
  isOwner: boolean;
  sessionTenantId: string | undefined;
  availableTenants: Array<{ id: string; name: string }>;
  membershipCount: number;
}) => {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isSwitchingOpen, setIsSwitchingOpen] = useState(false);
  const [isDeletingOpen, setIsDeletingOpen] = useState(false);

  const isActiveTenant = tenantId === sessionTenantId;
  const canDelete = isOwner && membershipCount > 1;

  return (
    <>
      <Modal open={isEditOpen} onOpenChange={setIsEditOpen} title="">
        <EditTenantForm
          tenantId={tenantId}
          tenantName={tenantName}
          setIsOpen={setIsEditOpen}
        />
      </Modal>
      <AlertModal
        open={isSwitchingOpen}
        onOpenChange={setIsSwitchingOpen}
        title="Confirm organization switch"
        description="The session will be updated and the page will reload to apply the change."
      >
        <SwitchTenantForm tenantId={tenantId} setIsOpen={setIsSwitchingOpen} />
      </AlertModal>
      <AlertModal
        open={isDeletingOpen}
        onOpenChange={setIsDeletingOpen}
        title="Delete organization"
        description="This will permanently delete the organization and all its data. Users with no other organizations will lose access. This action cannot be undone."
      >
        <DeleteTenantForm
          tenantId={tenantId}
          tenantName={tenantName}
          isActiveTenant={isActiveTenant}
          availableTenants={availableTenants}
          setIsOpen={setIsDeletingOpen}
        />
      </AlertModal>
      <Card variant="inner" className="p-2">
        <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
          <Badge variant="secondary">{membership.attributes.role}</Badge>

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

          <div className="ml-auto flex items-center gap-2">
            {isOwner && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setIsEditOpen(true)}
              >
                Edit
              </Button>
            )}
            {canDelete && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="text-destructive hover:text-destructive"
                onClick={() => setIsDeletingOpen(true)}
              >
                Delete
              </Button>
            )}
            {isActiveTenant ? (
              <Badge
                variant="outline"
                className="border-emerald-600 text-emerald-600"
              >
                Active
              </Badge>
            ) : (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setIsSwitchingOpen(true)}
              >
                Switch
              </Button>
            )}
          </div>
        </div>
      </Card>
    </>
  );
};
