import React, { Suspense } from "react";

import { getRolesByIds } from "@/actions/roles/roles";
import { getProfileInfo } from "@/actions/users/users";
import { getUserMemberships } from "@/actions/users/users";
import { ContentLayout } from "@/components/ui";
import { SkeletonUserInfo } from "@/components/users/profile/skeleton-user-info";
import { UserInfo } from "@/components/users/profile/user-info";

export default async function Profile() {
  return (
    <ContentLayout title="User Profile" icon="ci:users">
      <div className="min-h-screen">
        <div className="w-full md:w-1/2 lg:w-1/2 xl:w-1/3">
          <h2 className="mb-4 text-xl font-bold">My Profile</h2>
          <p className="mb-6 text-sm text-gray-500">
            Information about your account and memberships in Prowler.
          </p>
          <Suspense fallback={<SkeletonUserInfo />}>
            <SSRDataUser />
          </Suspense>
        </div>
      </div>
    </ContentLayout>
  );
}

const SSRDataUser = async () => {
  // Get user profile information
  const userProfile = await getProfileInfo();
  if (!userProfile?.data) {
    return <UserInfo user={null} />;
  }

  // Extract the role IDs from the user profile
  const roleIds =
    userProfile.data.relationships?.roles?.data?.map(
      (role: { id: string }) => role.id,
    ) || [];

  // Fetch role details if there are any role IDs
  const roleDetails =
    roleIds.length > 0 ? await getRolesByIds(roleIds) : { data: [] };

  // Fetch user membership details
  const memberships = await getUserMemberships(userProfile.data.id);

  return (
    <UserInfo
      user={userProfile?.data}
      roleDetails={roleDetails?.data || []}
      membershipDetails={memberships?.data || []}
    />
  );
};
