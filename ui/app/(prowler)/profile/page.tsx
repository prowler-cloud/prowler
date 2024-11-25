import { Spacer } from "@nextui-org/react";
import { redirect } from "next/navigation";
import React from "react";

// import { getUserByMe } from "@/actions/auth/auth";
import { auth } from "@/auth.config";
import { Header } from "@/components/ui";

export default async function Profile() {
  const session = await auth();

  if (!session?.user) {
    // redirect("/sign-in?returnTo=/profile");
    redirect("/sign-in");
  }

  // const user = await getUserByMe();

  return (
    <>
      <Header title="User Profile" icon="ci:users" />
      <Spacer y={4} />
      <Spacer y={6} />
      <pre>{JSON.stringify(session.user, null, 2)}</pre>
      <pre>{JSON.stringify(session.userId, null, 2)}</pre>
      <pre>{JSON.stringify(session.tenantId, null, 2)}</pre>
      <pre>{JSON.stringify(session, null, 2)}</pre>
    </>
  );
}
