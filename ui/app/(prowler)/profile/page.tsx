import React, { Suspense } from "react";

import { getRolesByIds } from "@/actions/roles/roles";
import { getProfileInfo } from "@/actions/users/users";
import { getUserMemberships } from "@/actions/users/users";
import { ContentLayout } from "@/components/ui";
import { UserBasicInfoCard } from "@/components/users/profile";
import { MembershipsCard } from "@/components/users/profile/memberships-card";
import { RolesCard } from "@/components/users/profile/roles-card";
import { SkeletonUserInfo } from "@/components/users/profile/skeleton-user-info";
import { RoleDetail } from "@/types/users/users";

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
  const userProfile = await getProfileInfo();
  if (!userProfile?.data) {
    return null;
  }

  const roleIds =
    userProfile.data.relationships?.roles?.data?.map(
      (role: { id: string }) => role.id,
    ) || [];

  const roleDetails =
    roleIds.length > 0 ? await getRolesByIds(roleIds) : { data: [] };

  const memberships = await getUserMemberships(userProfile.data.id);

  const roleDetailsMap = roleDetails.data.reduce(
    (acc: Record<string, RoleDetail>, role: RoleDetail) => {
      acc[role.id] = role;
      return acc;
    },
    {} as Record<string, RoleDetail>,
  );

  return (
    <div className="flex flex-col gap-6">
      <UserBasicInfoCard user={userProfile?.data} />
      <RolesCard roles={roleDetails?.data || []} roleDetails={roleDetailsMap} />
      <MembershipsCard memberships={memberships?.data || []} />
    </div>
  );
};
