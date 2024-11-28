import { Suspense } from "react";

import { getInvitationInfoById } from "@/actions/invitations/invitation";
import { InvitationDetails } from "@/components/invitations";
import { SkeletonInvitationInfo } from "@/components/invitations/workflow";
import { SearchParamsProps } from "@/types";

export default async function CheckDetailsPage({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <Suspense key={searchParamsKey} fallback={<SkeletonInvitationInfo />}>
      <SSRDataInvitation searchParams={searchParams} />
    </Suspense>
  );
}

const SSRDataInvitation = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const invitationId = searchParams.id;

  if (!invitationId) {
    return <div>Invalid invitation ID</div>;
  }

  const invitationData = (await getInvitationInfoById(invitationId as string))
    .data;

  if (!invitationData) {
    return <div>Invitation not found</div>;
  }

  const { attributes, links } = invitationData;

  return <InvitationDetails attributes={attributes} selfLink={links.self} />;
};
