"use client";

import Link from "next/link";

import { Button } from "@/components/shadcn";

import { AddIcon } from "../icons";

export const AddProviderButton = () => {
  return (
    <Button asChild>
      <Link href="/providers/connect-account">
        Add Cloud Provider
        <AddIcon size={20} />
      </Link>
    </Button>
  );
};
