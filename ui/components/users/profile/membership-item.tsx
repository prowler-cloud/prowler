"use client";

import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { DateWithTime } from "@/components/shadcn/entities";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { Modal } from "@/components/shadcn/modal";
import { EditTenantForm } from "@/components/users/forms";
import { DeleteTenantForm } from "@/components/users/forms/delete-tenant-form";
import { SwitchTenantForm } from "@/components/users/forms/switch-tenant-form";
import { MembershipDetailData, TenantOption } from "@/types/users";

export const MembershipItem = ({
  membership,
  tenantName,
  tenantId,
  isOrgOwner,
  sessionTenantId,
  availableTenants,
  membershipCount,
}: {
  membership: MembershipDetailData;
  tenantName: string;
  tenantId: string;
  isOrgOwner: boolean;
  sessionTenantId: string | undefined;
  availableTenants: TenantOption[];
  membershipCount: number;
}) => {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isSwitchingOpen, setIsSwitchingOpen] = useState(false);
  const [isDeletingOpen, setIsDeletingOpen] = useState(false);

  const isActiveTenant = tenantId === sessionTenantId;
  const isLastTenant = membershipCount === 1;

  return (
    <>
      <Modal open={isEditOpen} onOpenChange={setIsEditOpen} title="">
        <EditTenantForm
          tenantId={tenantId}
          tenantName={tenantName}
          setIsOpen={setIsEditOpen}
        />
      </Modal>
      <Modal
        open={isSwitchingOpen}
        onOpenChange={setIsSwitchingOpen}
        title="Confirm organization switch"
        description="The session will be updated and the page will reload to apply the change."
      >
        <SwitchTenantForm tenantId={tenantId} setIsOpen={setIsSwitchingOpen} />
      </Modal>
      <Modal
        open={isDeletingOpen}
        onOpenChange={setIsDeletingOpen}
        title="Delete organization"
        description={
          isLastTenant
            ? "This will permanently delete the organization and all its data. This action cannot be undone."
            : "This will permanently delete the organization and all its data. Users with no other organizations will lose access. This action cannot be undone."
        }
      >
        <DeleteTenantForm
          tenantId={tenantId}
          tenantName={tenantName}
          isActiveTenant={isActiveTenant}
          isLastTenant={isLastTenant}
          availableTenants={availableTenants}
          setIsOpen={setIsDeletingOpen}
        />
      </Modal>
      <Card variant="inner" className="p-2">
        <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
          <span className="flex w-16 shrink-0">
            <Badge variant="secondary">{membership.attributes.role}</Badge>
          </span>

          <div className="flex min-w-0 flex-1 items-center gap-2">
            <InfoField
              label="Name"
              inline
              variant="transparent"
              className="min-w-0 [&>div]:min-w-0"
            >
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="block truncate font-semibold">
                    {tenantName}
                  </span>
                </TooltipTrigger>
                <TooltipContent>{tenantName}</TooltipContent>
              </Tooltip>
            </InfoField>
            {isActiveTenant && (
              <Badge variant="success" className="shrink-0">
                Active
              </Badge>
            )}
          </div>

          <InfoField
            label="Joined on"
            inline
            variant="transparent"
            className="shrink-0"
          >
            <DateWithTime
              inline
              showTime={false}
              dateTime={membership.attributes.date_joined}
            />
          </InfoField>

          {/* Fixed-width slots keep Edit/Delete/Switch aligned across rows */}
          <div className="flex shrink-0 items-center gap-2 self-end sm:self-auto">
            <span className="flex w-18 justify-center">
              {isOrgOwner && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsEditOpen(true)}
                >
                  Edit
                </Button>
              )}
            </span>
            <span className="flex w-18 justify-center">
              {isOrgOwner && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="text-text-error-primary"
                  onClick={() => setIsDeletingOpen(true)}
                >
                  Delete
                </Button>
              )}
            </span>
            <span className="flex w-18 justify-center">
              {!isActiveTenant && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsSwitchingOpen(true)}
                >
                  Switch
                </Button>
              )}
            </span>
          </div>
        </div>
      </Card>
    </>
  );
};
