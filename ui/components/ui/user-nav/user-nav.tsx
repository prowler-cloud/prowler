"use client";

import { LogOut, User } from "lucide-react";
import { useSession } from "next-auth/react";

import { logOut } from "@/actions/auth";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar/avatar";
import { Button } from "@/components/ui/button/button";
import { CustomLink } from "@/components/ui/custom/custom-link";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu/dropdown-menu";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip/tooltip";

export const UserNav = () => {
  const { data: session } = useSession();

  if (!session?.user) return null;

  const { name, email, companyName } = session.user;

  return (
    <DropdownMenu>
      <TooltipProvider disableHoverableContent>
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                className="relative h-8 w-8 rounded-full"
              >
                <Avatar className="h-8 w-8">
                  <AvatarImage src="#" alt="Avatar" />
                  <AvatarFallback className="bg-transparent text-xs font-bold">
                    {name.includes(" ")
                      ? name
                          .split(" ")
                          .map((word) => word.charAt(0))
                          .join("")
                      : name.charAt(0)}
                  </AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent side="bottom">Profile</TooltipContent>
        </Tooltip>
      </TooltipProvider>

      <DropdownMenuContent className="w-56" align="end" forceMount>
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col space-y-1">
            <p className="text-small font-medium leading-none">
              {name}
              {companyName && (
                <span className="text-xs">{` | ${companyName}`}</span>
              )}
            </p>
            <p className="text-muted-foreground text-xs leading-none">
              {email}
            </p>
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuItem className="hover:cursor-pointer" asChild>
            <CustomLink
              href="/profile"
              className="flex items-center font-normal text-prowler-black dark:text-prowler-white"
              target="_self"
            >
              <User className="text-muted-foreground mr-3 h-4 w-4" />
              Account
            </CustomLink>
          </DropdownMenuItem>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          className="hover:cursor-pointer"
          onClick={() => logOut()}
        >
          <LogOut className="text-muted-foreground mr-3 h-4 w-4" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
