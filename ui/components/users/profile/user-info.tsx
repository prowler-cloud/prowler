"use client";

import { RoleDetailData, UserInfoProps } from "@/types/users/profile";

import { MembershipsCard } from "./memberships-card";
import { RolesCard } from "./roles-card";
import { UserBasicInfoCard } from "./user-basic-info-card";

export const UserInfo = ({
  user,
  roleDetails = [],
  membershipDetails = [],
}: UserInfoProps) => {
  if (!user) {
    return null;
  }

  const { relationships } = user;
  const roles = relationships.roles?.data || [];

  // Create a role ID to name mapping for easier lookup
  const roleDetailsMap = roleDetails.reduce(
    (acc: Record<string, RoleDetailData>, role: RoleDetailData) => {
      acc[role.id] = role;
      return acc;
    },
    {} as Record<string, RoleDetailData>,
  );

  return (
    <div className="flex flex-col gap-6">
      <UserBasicInfoCard user={user} />
      <RolesCard roles={roles} roleDetails={roleDetailsMap} />
      <MembershipsCard memberships={membershipDetails} />
    </div>
  );
};
