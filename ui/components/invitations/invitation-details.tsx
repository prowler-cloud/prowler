"use client";

import Link from "next/link";

import { AddIcon } from "../icons";
import { Button, Card, CardContent, CardHeader } from "../shadcn";
import { Separator } from "../shadcn/separator/separator";
import { CodeSnippet } from "../ui/code-snippet/code-snippet";
import { DateWithTime } from "../ui/entities";

interface InvitationDetailsProps {
  attributes: {
    email: string;
    state: string;
    token: string;
    expires_at: string;
    inserted_at: string;
    updated_at: string;
  };
  relationships?: {
    inviter: {
      data: {
        id: string;
      };
    };
  };
  selfLink: string;
}

const InfoField = ({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) => (
  <div className="flex min-w-0 flex-col gap-1">
    <span className="text-text-neutral-secondary text-xs font-bold">
      {label}
    </span>
    <div className="border-border-input-primary bg-bg-input-primary flex min-w-0 items-center overflow-hidden rounded-lg border p-3">
      <span className="text-small text-text-neutral-primary min-w-0 truncate">
        {children}
      </span>
    </div>
  </div>
);

export const InvitationDetails = ({ attributes }: InvitationDetailsProps) => {
  // window.location.origin to get the current base URL
  const baseUrl =
    typeof window !== "undefined"
      ? window.location.origin
      : "http://localhost:3000";

  const invitationLink = `${baseUrl}/invitation/accept?invitation_token=${attributes.token}`;

  return (
    <div className="flex flex-col gap-x-4 gap-y-8">
      <Card variant="base" padding="lg">
        <CardHeader>Invitation details</CardHeader>
        <CardContent>
          <div className="flex flex-col gap-3">
            <InfoField label="Email">{attributes.email}</InfoField>

            <InfoField label="Token">{attributes.token}</InfoField>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <InfoField label="State">
                <span className="capitalize">{attributes.state}</span>
              </InfoField>

              <InfoField label="Expires At">
                <DateWithTime dateTime={attributes.expires_at} inline />
              </InfoField>

              <InfoField label="Created At">
                <DateWithTime dateTime={attributes.inserted_at} inline />
              </InfoField>

              <InfoField label="Updated At">
                <DateWithTime dateTime={attributes.updated_at} inline />
              </InfoField>
            </div>
          </div>

          <Separator className="my-4" />
          <h3 className="text-text-neutral-primary pb-2 text-sm font-bold">
            Share this link with the user:
          </h3>

          <CodeSnippet value={invitationLink} className="max-w-full" />
        </CardContent>
      </Card>
      <div className="flex w-full items-center justify-end">
        <Button asChild size="default" className="gap-2">
          <Link href="/invitations/">
            Back to Invitations
            <AddIcon size={20} />
          </Link>
        </Button>
      </div>
    </div>
  );
};
