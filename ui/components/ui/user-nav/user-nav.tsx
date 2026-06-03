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
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
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

  // Derive the replay list entirely from the registry so adding or reordering
  // flows never requires editing this component. Selecting an entry hands off
  // to the target route's OnboardingTrigger via the `?onboarding=<id>` param,
  // which force-starts that single flow only — no guided sequence is started.
  const flows = getOrderedFlows();

  const replayFlow = (route: string, id: string) => {
    router.push(`${route}?onboarding=${id}`);
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon-sm"
          // Avatar is round; ghost icon button + rounded-full instead of an ad-hoc bordered variant
          className="rounded-full"
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
        <DropdownMenuSub>
          <DropdownMenuSubTrigger className="cursor-pointer">
            <Compass />
            Product tour
          </DropdownMenuSubTrigger>
          <DropdownMenuSubContent>
            {flows.map((flow) => (
              <DropdownMenuItem
                key={flow.id}
                className="cursor-pointer"
                onSelect={() => replayFlow(flow.route, flow.id)}
              >
                {flow.title}
              </DropdownMenuItem>
            ))}
          </DropdownMenuSubContent>
        </DropdownMenuSub>
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
