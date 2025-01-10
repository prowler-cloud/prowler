"use client";

import { Card, CardBody, Divider, Snippet } from "@nextui-org/react";

import { AddIcon } from "../icons";
import { CustomButton } from "../ui/custom";
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

export const InvitationDetails = ({ attributes }: InvitationDetailsProps) => {
  // window.location.origin to get the current base URL
  const baseUrl =
    typeof window !== "undefined"
      ? window.location.origin
      : "http://localhost:3000";

  const invitationLink = `${baseUrl}/invitations/check-details?id=${attributes.token}`;

  return (
    <div className="flex flex-col gap-x-4 gap-y-8">
      <Card
        isBlurred
        className="border-none bg-background/60 dark:bg-prowler-blue-800"
        shadow="sm"
      >
        <CardBody>
          <h2 className="text-2xl font-bold text-foreground/90">
            Invitation Details
          </h2>
          <Divider className="my-4" />

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <strong className="text-default-500">Email:</strong>
              <span>{attributes.email}</span>
            </div>

            <div className="flex items-center justify-between">
              <strong className="text-default-500">State:</strong>
              <span className="capitalize">{attributes.state}</span>
            </div>

            <div className="flex items-center justify-between">
              <strong className="text-default-500">Token:</strong>
              <span>{attributes.token}</span>
            </div>

            <div className="flex items-center justify-between">
              <strong className="text-default-500">Expires At:</strong>
              <DateWithTime dateTime={attributes.expires_at} />
            </div>

            <div className="flex items-center justify-between">
              <strong className="text-default-500">Inserted At:</strong>
              <DateWithTime dateTime={attributes.inserted_at} />
            </div>

            <div className="flex items-center justify-between">
              <strong className="text-default-500">Updated At:</strong>
              <DateWithTime dateTime={attributes.updated_at} />
            </div>
          </div>

          <Divider className="my-4" />
          <h3 className="pb-2 text-xl font-bold text-foreground/90">
            Share this link with the user:
          </h3>

          <div className="flex flex-col items-start justify-between">
            <Snippet
              classNames={{
                base: "mx-auto",
              }}
              hideSymbol
              variant="bordered"
              className="overflow-hidden text-ellipsis whitespace-nowrap"
            >
              <p className="no-scrollbar w-96 overflow-hidden overflow-x-scroll text-ellipsis whitespace-nowrap text-sm">
                {invitationLink}
              </p>
            </Snippet>
          </div>
        </CardBody>
      </Card>
      <div className="flex w-full items-center justify-end">
        <CustomButton
          asLink="/invitations/"
          ariaLabel="Send Invitation"
          variant="solid"
          color="action"
          size="md"
          endContent={<AddIcon size={20} />}
        >
          Back to Invitations
        </CustomButton>
      </div>
    </div>
  );
};
