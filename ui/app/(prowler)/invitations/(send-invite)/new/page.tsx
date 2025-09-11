import React from "react";
import { Suspense } from "react";

import { getRoles } from "@/actions/roles";
import { SkeletonInvitationInfo } from "@/components/invitations/workflow";
import { SendInvitationForm } from "@/components/invitations/workflow/forms/send-invitation-form";

export default async function SendInvitationPage() {
  const rolesData = await getRoles({});

  return (
    <Suspense fallback={<SkeletonInvitationInfo />}>
      <SSRSendInvitation rolesData={rolesData?.data || []} />
    </Suspense>
  );
}

const SSRSendInvitation = ({ rolesData }: { rolesData: Array<any> }) => {
  const hasRoles = rolesData && rolesData.length > 0;

  return (
    <SendInvitationForm
      roles={rolesData.map((role) => ({
        id: role.id,
        name: role.attributes.name,
      }))}
      defaultRole={!hasRoles ? "admin" : undefined}
      isSelectorDisabled={!hasRoles}
    />
  );
};
