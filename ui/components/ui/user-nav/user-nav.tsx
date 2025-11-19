"use client";

import { LogOut } from "lucide-react";
import { useSession } from "next-auth/react";

import { logOut } from "@/actions/auth";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar/avatar";
import { CustomLink } from "@/components/ui/custom/custom-link";

export const UserNav = () => {
  const { data: session } = useSession();

  if (!session?.user) return null;

  const { name } = session.user;

  const initials = name.includes(" ")
    ? name
        .split(" ")
        .map((word) => word.charAt(0))
        .join("")
    : name.charAt(0);

  return (
    <div className="flex items-center gap-2">
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon-sm"
            className="border-border-input-primary-fill rounded-full"
            asChild
          >
            <CustomLink href="/profile" target="_self" aria-label="Account">
              <Avatar className="h-8 w-8">
                <AvatarImage src="#" alt="Avatar" />
                <AvatarFallback className="bg-transparent text-xs font-bold">
                  {initials}
                </AvatarFallback>
              </Avatar>
            </CustomLink>
          </Button>
        </TooltipTrigger>
        <TooltipContent>Account Settings</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon-sm"
            className="border-border-input-primary-fill rounded-full"
            onClick={() => logOut()}
            aria-label="Sign out"
          >
            <LogOut />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Sign Out</TooltipContent>
      </Tooltip>
    </div>
  );
};
