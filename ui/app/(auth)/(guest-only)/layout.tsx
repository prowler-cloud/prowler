import { redirect } from "next/navigation";
import { ReactNode } from "react";

import { auth } from "@/auth.config";

export default async function GuestOnlyLayout({
  children,
}: {
  children: ReactNode;
}) {
  const session = await auth();

  if (session?.user) {
    redirect("/");
  }

  return <>{children}</>;
}
