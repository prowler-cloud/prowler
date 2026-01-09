"use client";

import { SettingsIcon } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn";

export const MutedFindingsConfigButton = () => {
  return (
    <Button variant="outline" asChild>
      <Link href="/mutelist">
        <SettingsIcon size={20} />
        Configure Mutelist
      </Link>
    </Button>
  );
};
