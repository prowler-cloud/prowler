import "@/styles/globals.css";

import { Spacer } from "@heroui/spacer";
import React from "react";

import { WorkflowSendInvite } from "@/components/invitations/workflow";
import { NavigationHeader } from "@/components/ui";

interface InvitationLayoutProps {
  children: React.ReactNode;
}

export default function InvitationLayout({ children }: InvitationLayoutProps) {
  return (
    <>
      <NavigationHeader
        title="Send Invitation"
        icon="icon-park-outline:close-small"
        href="/invitations"
      />
      <Spacer y={16} />
      <div className="grid grid-cols-1 gap-8 px-4 lg:grid-cols-12 lg:px-0">
        <div className="order-1 my-auto h-full lg:col-span-4 lg:col-start-2">
          <WorkflowSendInvite />
        </div>
        <div className="order-2 my-auto lg:col-span-5 lg:col-start-6">
          {children}
        </div>
      </div>
    </>
  );
}
