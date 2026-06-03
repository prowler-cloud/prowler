"use client";

import { Compass, LogOut, Settings } from "lucide-react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";

import { logOut } from "@/actions/auth";
import { Button } from "@/components/shadcn/button/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/shadcn/dropdown/dropdown";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar/avatar";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { getOrderedFlows } from "@/lib/onboarding";

export const UserNav = () => {
  const { data: session } = useSession();
  const router = useRouter();

  if (!session?.user) return null;

  const { name } = session.user;

  const initials = name.includes(" ")
    ? name
        .split(" ")
        .map((word) => word.charAt(0))
        .join("")
    : name.charAt(0);

  // Derive the restart destination from the registry so adding or reordering
  // flows never requires editing this component. The trigger mounted on the
  // target route consumes the `?onboarding=<id>` param and force-starts the tour.
  const firstFlow = getOrderedFlows()[0];

  const startProductTour = () => {
    if (!firstFlow) return;
    router.push(`${firstFlow.route}?onboarding=${firstFlow.id}`);
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="icon-sm"
          className="border-border-input-primary-fill rounded-full"
          aria-label="Account menu"
        >
          <Avatar className="h-8 w-8">
            <AvatarImage src="#" alt="Avatar" />
            <AvatarFallback className="bg-transparent text-xs font-bold">
              {initials}
            </AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>{name}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild className="cursor-pointer">
          <CustomLink href="/profile" target="_self">
            <Settings />
            Account Settings
          </CustomLink>
        </DropdownMenuItem>
        {firstFlow && (
          <DropdownMenuItem
            className="cursor-pointer"
            onSelect={startProductTour}
          >
            <Compass />
            Product tour
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          variant="destructive"
          className="cursor-pointer"
          onSelect={() => logOut()}
        >
          <LogOut />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
