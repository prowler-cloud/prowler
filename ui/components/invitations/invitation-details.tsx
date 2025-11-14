"use client";

import { Snippet } from "@heroui/snippet";
import Link from "next/link";

import { AddIcon } from "../icons";
import { Button, Card, CardContent, CardHeader } from "../shadcn";
import { Separator } from "../shadcn/separator/separator";
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
  <div className="flex flex-col gap-1">
    <span className="text-xs font-bold text-gray-500">{label}</span>
    <div className="flex items-center rounded-lg bg-gray-50 p-3">
      <span className="text-small text-gray-900">{children}</span>
    </div>
  </div>
);

export const InvitationDetails = ({ attributes }: InvitationDetailsProps) => {
  // window.location.origin to get the current base URL
  const baseUrl =
    typeof window !== "undefined"
      ? window.location.origin
      : "http://localhost:3000";

  const invitationLink = `${baseUrl}/sign-up?invitation_token=${attributes.token}`;

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
          <h3 className="pb-2 text-sm font-bold text-gray-900 dark:text-gray-100">
            Share this link with the user:
          </h3>

          <div className="flex flex-col items-start justify-between">
            <Snippet
              classNames={{
                base: "mx-auto",
              }}
              hideSymbol
              variant="bordered"
              className="overflow-hidden bg-gray-50 py-1 text-ellipsis whitespace-nowrap dark:bg-slate-800"
            >
              <p className="no-scrollbar w-fit overflow-hidden overflow-x-scroll text-sm text-ellipsis whitespace-nowrap">
                {invitationLink}
              </p>
            </Snippet>
          </div>
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
