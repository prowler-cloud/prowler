import React, { Suspense } from "react";

import { getSamlConfig } from "@/actions/integrations/saml";
import { getUserInfo } from "@/actions/users/users";
import { SamlIntegrationCard } from "@/components/integrations/saml/saml-integration-card";
import { ContentLayout } from "@/components/ui";
import { ApiKeysCard, UserBasicInfoCard } from "@/components/users/profile";
import { MembershipsCard } from "@/components/users/profile/memberships-card";
import { RolesCard } from "@/components/users/profile/roles-card";
import { SkeletonUserInfo } from "@/components/users/profile/skeleton-user-info";
import { SearchParamsProps } from "@/types";
import {
  MembershipDetailData,
  RoleDetail,
  TenantDetailData,
  UserProfileResponse,
} from "@/types/users";

export default async function Profile({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;

  return (
    <ContentLayout title="User Profile" icon="lucide:users">
      <Suspense fallback={<SkeletonUserInfo />}>
        <SSRDataUser searchParams={resolvedSearchParams} />
      </Suspense>
    </ContentLayout>
  );
}

const SSRDataUser = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const userProfile = (await getUserInfo()) as UserProfileResponse | undefined;
  if (!userProfile?.data) {
    return null;
  }

  const userData = userProfile.data;

  const roleDetails =
    userProfile.included?.filter(
      (item): item is RoleDetail => item.type === "roles",
    ) || [];

  const membershipsIncluded =
    userProfile.included?.filter(
      (item): item is MembershipDetailData => item.type === "memberships",
    ) || [];

  const tenantsIncluded =
    userProfile.included?.filter(
      (item): item is TenantDetailData => item.type === "tenants",
    ) || [];

  const roleDetailsMap = roleDetails.reduce<Record<string, RoleDetail>>(
    (acc, role) => {
      acc[role.id] = role;
      return acc;
    },
    {},
  );

  const tenantsMap = tenantsIncluded.reduce<Record<string, TenantDetailData>>(
    (acc, tenant) => {
      acc[tenant.id] = tenant;
      return acc;
    },
    {},
  );

  const firstUserMembership = membershipsIncluded.find(
    (m) => m.relationships?.user?.data?.id === userData.id,
  );

  const userTenantId = firstUserMembership?.relationships?.tenant?.data?.id;

  const userRoleIds =
    userData.relationships?.roles?.data?.map((r) => r.id) || [];

  const hasManageAccount = roleDetails.some(
    (role) =>
      role.attributes.manage_account === true && userRoleIds.includes(role.id),
  );

  const hasManageIntegrations = roleDetails.some(
    (role) =>
      role.attributes.manage_integrations === true &&
      userRoleIds.includes(role.id),
  );

  const isOwner = membershipsIncluded.some(
    (m) =>
      m.attributes.role === "owner" &&
      m.relationships?.user?.data?.id === userData.id,
  );

  const samlConfig = hasManageIntegrations ? await getSamlConfig() : undefined;

  return (
    <div className="flex w-full flex-col gap-6">
      <UserBasicInfoCard user={userData} tenantId={userTenantId || ""} />
      <div className="flex flex-col gap-6 xl:flex-row">
        <div className="flex w-full flex-col gap-6 xl:max-w-[50%]">
          <RolesCard roles={roleDetails} roleDetails={roleDetailsMap} />
          {hasManageIntegrations && (
            <SamlIntegrationCard samlConfig={samlConfig?.data?.[0]} />
          )}
        </div>
        <div className="flex w-full flex-col gap-6 xl:max-w-[50%]">
          <MembershipsCard
            memberships={membershipsIncluded}
            tenantsMap={tenantsMap}
            isOwner={isOwner && hasManageAccount}
          />
          {hasManageAccount && <ApiKeysCard searchParams={searchParams} />}
        </div>
      </div>
    </div>
  );
};
