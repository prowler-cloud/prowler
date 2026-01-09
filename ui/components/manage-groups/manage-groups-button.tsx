"use client";

import { SettingsIcon } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn";

export const ManageGroupsButton = () => {
  return (
    <Button asChild variant="outline">
      <Link href="/manage-groups">
        <SettingsIcon size={20} />
        Manage Groups
      </Link>
    </Button>
  );
};
