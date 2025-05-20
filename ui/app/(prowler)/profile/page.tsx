import React, { Suspense } from "react";

import { getRolesByIds } from "@/actions/roles/roles";
import { getUserInfo } from "@/actions/users/users";
import { getUserMemberships } from "@/actions/users/users";
import { ContentLayout } from "@/components/ui";
import { UserBasicInfoCard } from "@/components/users/profile";
import { MembershipsCard } from "@/components/users/profile/memberships-card";
import { RolesCard } from "@/components/users/profile/roles-card";
import { SkeletonUserInfo } from "@/components/users/profile/skeleton-user-info";
import { RoleDetail } from "@/types/users/users";

import { getAllTenants } from "../../../actions/users/tenants";

// Definir la interfaz para Tenant
interface Tenant {
  type: string;
  id: string;
  attributes: {
    name: string;
  };
  relationships: {
    memberships: {
      meta: {
        count: number;
      };
      data: Array<{
        type: string;
        id: string;
      }>;
    };
  };
}

export default async function Profile() {
  return (
    <ContentLayout title="User Profile" icon="ci:users">
      <div className="w-full md:w-1/2 lg:w-1/2 xl:w-1/3 2xl:w-1/4">
        <Suspense fallback={<SkeletonUserInfo />}>
          <SSRDataUser />
        </Suspense>
      </div>
    </ContentLayout>
  );
}

const SSRDataUser = async () => {
  const userProfile = await getUserInfo();
  if (!userProfile?.data) {
    return null;
  }
  console.log("USER PROFILE ================================================");
  console.log(JSON.stringify(userProfile, null, 2));

  const roleIds =
    userProfile.data.relationships?.roles?.data?.map(
      (role: { id: string }) => role.id,
    ) || [];

  const roleDetails =
    roleIds.length > 0 ? await getRolesByIds(roleIds) : { data: [] };

  const memberships = await getUserMemberships(userProfile.data.id);
  console.log("MEMBERSHIPS ================================================");
  console.log(JSON.stringify(memberships, null, 2));
  const roleDetailsMap = roleDetails.data.reduce(
    (acc: Record<string, RoleDetail>, role: RoleDetail) => {
      acc[role.id] = role;
      return acc;
    },
    {} as Record<string, RoleDetail>,
  );

  const tenants = await getAllTenants();
  console.log("TENANTS ================================================");
  console.log(JSON.stringify(tenants, null, 2));

  const userMembershipIds =
    userProfile.data.relationships?.memberships?.data?.map(
      (membership: { id: string }) => membership.id,
    ) || [];

  const userTenant = tenants?.data?.find((tenant: Tenant) =>
    tenant.relationships?.memberships?.data?.some(
      (membership: { id: string }) => userMembershipIds.includes(membership.id),
    ),
  );

  return (
    <div className="flex flex-col gap-6">
      <UserBasicInfoCard user={userProfile?.data} tenantId={userTenant?.id} />
      <RolesCard roles={roleDetails?.data || []} roleDetails={roleDetailsMap} />
      <MembershipsCard memberships={memberships?.data || []} />
    </div>
  );
};
