"use client";

import { useState } from "react";

import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { CreateTenantForm } from "@/components/users/forms/create-tenant-form";
import { MembershipDetailData, TenantDetailData } from "@/types/users";

import { MembershipItem } from "./membership-item";

interface MembershipsCardClientProps {
  memberships: MembershipDetailData[];
  tenantsMap: Record<string, TenantDetailData>;
  isOwner: boolean;
  hasManageAccount: boolean;
  sessionTenantId: string | undefined;
}

export const MembershipsCardClient = ({
  memberships,
  tenantsMap,
  isOwner,
  hasManageAccount,
  sessionTenantId,
}: MembershipsCardClientProps) => {
  const [isCreateOpen, setIsCreateOpen] = useState(false);

  // Compute available tenants for delete target Select
  const availableTenants = memberships.map((m) => {
    const id = m.relationships.tenant.data.id;
    return { id, name: tenantsMap[id]?.attributes.name || id };
  });

  return (
    <>
      <Modal
        open={isCreateOpen}
        onOpenChange={setIsCreateOpen}
        title="Create organization"
      >
        <CreateTenantForm setIsOpen={setIsCreateOpen} />
      </Modal>
      <Card variant="base" padding="none" className="p-4">
        <CardHeader>
          <div className="flex flex-col gap-1">
            <CardTitle>Organizations</CardTitle>
            <p className="text-xs text-gray-500">
              Organizations this user is associated with
            </p>
          </div>
          {hasManageAccount && (
            <CardAction>
              <Button
                variant="default"
                size="sm"
                onClick={() => setIsCreateOpen(true)}
              >
                Create organization
              </Button>
            </CardAction>
          )}
        </CardHeader>
        <CardContent>
          {memberships.length === 0 ? (
            <div className="text-sm text-gray-500">No memberships found.</div>
          ) : (
            <div className="flex flex-col gap-2">
              {memberships.map((membership) => {
                const tenantId = membership.relationships.tenant.data.id;
                return (
                  <MembershipItem
                    key={membership.id}
                    membership={membership}
                    tenantId={tenantId}
                    tenantName={tenantsMap[tenantId]?.attributes.name}
                    isOwner={isOwner}
                    sessionTenantId={sessionTenantId}
                    availableTenants={availableTenants.filter(
                      (t) => t.id !== tenantId,
                    )}
                    membershipCount={memberships.length}
                  />
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );
};
