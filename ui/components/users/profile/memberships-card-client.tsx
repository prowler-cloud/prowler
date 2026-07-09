"use client";

import { ColumnDef, Row } from "@tanstack/react-table";
import { ArrowRightLeft, Pencil, Trash2 } from "lucide-react";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { DateWithTime } from "@/components/shadcn/entities";
import { Modal } from "@/components/shadcn/modal";
import { DataTable, DataTableColumnHeader } from "@/components/shadcn/table";
import { EditTenantForm } from "@/components/users/forms";
import { CreateTenantForm } from "@/components/users/forms/create-tenant-form";
import { DeleteTenantForm } from "@/components/users/forms/delete-tenant-form";
import { SwitchTenantForm } from "@/components/users/forms/switch-tenant-form";
import {
  MembershipDetailData,
  TenantDetailData,
  TenantOption,
} from "@/types/users";

interface MembershipRow {
  id: string;
  tenantId: string;
  tenantName: string;
  role: string;
  dateJoined: string;
  isActiveTenant: boolean;
  isOrgOwner: boolean;
  availableTenants: TenantOption[];
  membershipCount: number;
}

interface MembershipsCardClientProps {
  memberships: MembershipDetailData[];
  tenantsMap: Record<string, TenantDetailData>;
  hasManageAccount: boolean;
  sessionTenantId: string | undefined;
}

const OrganizationNameCell = ({ name }: { name: string }) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <span className="block w-64 truncate text-sm font-medium whitespace-nowrap">
        {name}
      </span>
    </TooltipTrigger>
    <TooltipContent>{name}</TooltipContent>
  </Tooltip>
);

const MembershipRowActions = ({ row }: { row: Row<MembershipRow> }) => {
  const membership = row.original;
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isSwitchingOpen, setIsSwitchingOpen] = useState(false);
  const [isDeletingOpen, setIsDeletingOpen] = useState(false);

  const isLastTenant = membership.membershipCount === 1;
  const hasActions = membership.isOrgOwner || !membership.isActiveTenant;

  if (!hasActions) {
    return null;
  }

  return (
    <>
      <Modal open={isEditOpen} onOpenChange={setIsEditOpen} title="">
        <EditTenantForm
          tenantId={membership.tenantId}
          tenantName={membership.tenantName}
          setIsOpen={setIsEditOpen}
        />
      </Modal>
      <Modal
        open={isSwitchingOpen}
        onOpenChange={setIsSwitchingOpen}
        title="Confirm organization switch"
        description="The session will be updated and the page will reload to apply the change."
      >
        <SwitchTenantForm
          tenantId={membership.tenantId}
          setIsOpen={setIsSwitchingOpen}
        />
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
          tenantId={membership.tenantId}
          tenantName={membership.tenantName}
          isActiveTenant={membership.isActiveTenant}
          isLastTenant={isLastTenant}
          availableTenants={membership.availableTenants}
          setIsOpen={setIsDeletingOpen}
        />
      </Modal>
      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown>
          {membership.isOrgOwner && (
            <ActionDropdownItem
              icon={<Pencil />}
              label="Edit organization"
              onSelect={() => setIsEditOpen(true)}
            />
          )}
          {!membership.isActiveTenant && (
            <ActionDropdownItem
              icon={<ArrowRightLeft />}
              label="Switch organization"
              onSelect={() => setIsSwitchingOpen(true)}
            />
          )}
          {membership.isOrgOwner && (
            <ActionDropdownDangerZone>
              <ActionDropdownItem
                icon={<Trash2 />}
                label="Delete organization"
                destructive
                onSelect={() => setIsDeletingOpen(true)}
              />
            </ActionDropdownDangerZone>
          )}
        </ActionDropdown>
      </div>
    </>
  );
};

const membershipColumns: ColumnDef<MembershipRow>[] = [
  {
    accessorKey: "role",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Role" />
    ),
    cell: ({ row }) => <Badge variant="tag">{row.original.role}</Badge>,
    enableSorting: false,
  },
  {
    accessorKey: "isActiveTenant",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) =>
      row.original.isActiveTenant ? (
        <Badge variant="success">Active</Badge>
      ) : (
        <Badge variant="outline">Inactive</Badge>
      ),
    enableSorting: false,
  },
  {
    accessorKey: "tenantName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" />
    ),
    cell: ({ row }) => <OrganizationNameCell name={row.original.tenantName} />,
    enableSorting: false,
  },
  {
    accessorKey: "dateJoined",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Joined on" />
    ),
    cell: ({ row }) => (
      <DateWithTime
        inline
        showTime={false}
        dateTime={row.original.dateJoined}
      />
    ),
    enableSorting: false,
  },
  {
    id: "actions",
    header: ({ column }) => <DataTableColumnHeader column={column} title="" />,
    cell: ({ row }) => <MembershipRowActions row={row} />,
    enableSorting: false,
  },
];

export const MembershipsCardClient = ({
  memberships,
  tenantsMap,
  hasManageAccount,
  sessionTenantId,
}: MembershipsCardClientProps) => {
  const [isCreateOpen, setIsCreateOpen] = useState(false);

  // Compute available tenants for delete target Select
  const availableTenants = memberships.map((m) => {
    const id = m.relationships.tenant.data.id;
    return { id, name: tenantsMap[id]?.attributes.name || id };
  });

  const rows = memberships.map((membership) => {
    const tenantId = membership.relationships.tenant.data.id;
    const tenantName = tenantsMap[tenantId]?.attributes.name || tenantId;

    return {
      id: membership.id,
      tenantId,
      tenantName,
      role: membership.attributes.role,
      dateJoined: membership.attributes.date_joined,
      isActiveTenant: tenantId === sessionTenantId,
      isOrgOwner: hasManageAccount && membership.attributes.role === "owner",
      availableTenants: availableTenants.filter((t) => t.id !== tenantId),
      membershipCount: memberships.length,
    };
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
      <Card variant="inner" padding="none" className="gap-4 p-4 md:p-5">
        <CardHeader>
          <div className="flex flex-col gap-1">
            <CardTitle>Organizations</CardTitle>
            <p className="text-xs text-gray-500">
              Organizations this user is associated with.{" "}
              <CustomLink href="https://docs.prowler.com/user-guide/tutorials/prowler-app-multi-tenant">
                Learn more
              </CustomLink>
            </p>
          </div>
          <CardAction>
            <Button
              variant="default"
              size="sm"
              onClick={() => setIsCreateOpen(true)}
            >
              Create organization
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          {memberships.length === 0 ? (
            <div className="text-sm text-gray-500">No memberships found.</div>
          ) : (
            <DataTable columns={membershipColumns} data={rows} />
          )}
        </CardContent>
      </Card>
    </>
  );
};
