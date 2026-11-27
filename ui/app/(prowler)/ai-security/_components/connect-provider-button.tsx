"use client";

import { AddProviderButton } from "@/components/providers/add-provider-button";
import {
  Button,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { useAuth } from "@/hooks/use-auth";

/** Add Provider, disabled with the reason when the role cannot add one. */
export function ConnectProviderButton() {
  const { permissions } = useAuth();

  if (permissions.manage_providers === true) return <AddProviderButton />;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* Disabled buttons get no pointer events: the span takes the hover and focus. */}
        <span tabIndex={0} className="inline-flex">
          <Button disabled>Add Provider</Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        Your role needs the Manage Providers permission.
      </TooltipContent>
    </Tooltip>
  );
}
