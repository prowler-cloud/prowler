"use client";

import { LogOut } from "lucide-react";
import { useSession } from "next-auth/react";

import { logOut } from "@/actions/auth";
import { Button } from "@/components/shadcn/button/button";
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
      <Button
        variant="outline"
        size="icon-sm"
        className="border-input-border-fill rounded-full"
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

      <Button
        variant="ghost"
        size="icon-sm"
        className="border-input-border-fill rounded-full"
        onClick={() => logOut()}
        aria-label="Sign out"
      >
        <LogOut />
      </Button>
    </div>
  );
};
