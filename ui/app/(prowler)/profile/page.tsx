import React, { Suspense } from "react";

import { getSamlConfig } from "@/actions/integrations/saml";
import { getUserInfo } from "@/actions/users/users";
import { SamlIntegrationCard } from "@/components/integrations/saml/saml-integration-card";
import { ContentLayout } from "@/components/ui";
import { UserBasicInfoCard } from "@/components/users/profile";
import { MembershipsCard } from "@/components/users/profile/memberships-card";
import { RolesCard } from "@/components/users/profile/roles-card";
import { SkeletonUserInfo } from "@/components/users/profile/skeleton-user-info";
import { RoleDetail, TenantDetailData } from "@/types/users";

export default async function Profile() {
  return (
    <ContentLayout title="User Profile" icon="ci:users">
      <Suspense fallback={<SkeletonUserInfo />}>
        <SSRDataUser />
      </Suspense>
    </ContentLayout>
  );
}

const SSRDataUser = async () => {
  const userProfile = await getUserInfo();
  if (!userProfile?.data) {
    return null;
  }

  const roleDetails =
    userProfile.included?.filter((item: any) => item.type === "roles") || [];
  const membershipsIncluded =
    userProfile.included?.filter((item: any) => item.type === "memberships") ||
    [];

  const roleDetailsMap = roleDetails.reduce(
    (acc: Record<string, RoleDetail>, role: RoleDetail) => {
      acc[role.id] = role;
      return acc;
    },
    {} as Record<string, RoleDetail>,
  );

  const tenantsMap = {} as Record<string, TenantDetailData>;

  const firstUserMembership = membershipsIncluded.find(
    (m: any) => m.relationships?.user?.data?.id === userProfile.data.id,
  );
  const userTenantId = firstUserMembership?.relationships?.tenant?.data?.id;
  const tenantIdForCard = userTenantId || "";

  const userRoleIds =
    userProfile.data.relationships?.roles?.data?.map(
      (r: { id: string }) => r.id,
    ) || [];
  const hasManageAccount = roleDetails.some(
    (role: any) =>
      role.attributes?.manage_account === true && userRoleIds.includes(role.id),
  );
  const isOwner = membershipsIncluded.some(
    (m: any) =>
      m.attributes?.role === "owner" &&
      m.relationships?.user?.data?.id === userProfile.data.id,
  );
  const canManageAccount = isOwner && hasManageAccount;

  // Determine manage_integrations permission
  const hasManageIntegrations = roleDetails.some(
    (role: any) =>
      role.attributes?.manage_integrations === true &&
      userRoleIds.includes(role.id),
  );

  // Fetch SAML config only if user can manage integrations
  const samlConfig = hasManageIntegrations ? await getSamlConfig() : undefined;

  return (
    <div className="flex w-full flex-col gap-6">
      <UserBasicInfoCard user={userProfile?.data} tenantId={tenantIdForCard} />
      <div className="flex flex-col gap-6 xl:flex-row">
        <div className="w-full lg:w-2/3 xl:w-1/2">
          <RolesCard roles={roleDetails || []} roleDetails={roleDetailsMap} />
        </div>
        <div className="w-full lg:w-2/3 xl:w-1/2">
          <MembershipsCard
            memberships={membershipsIncluded || []}
            tenantsMap={tenantsMap}
            isOwner={canManageAccount}
          />
        </div>
      </div>
      {hasManageIntegrations && (
        <div className="w-full pr-0 lg:w-2/3 xl:w-1/2 xl:pr-3">
          <SamlIntegrationCard samlConfig={samlConfig?.data?.[0]} />
        </div>
      )}
    </div>
  );
};
