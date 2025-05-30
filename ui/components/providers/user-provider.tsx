"use client";

import { useEffect } from "react";

import { useUser } from "@/hooks/use-user";
import { UserProfileProps } from "@/types";

interface UserProviderProps {
  children: React.ReactNode;
  initialUser?: UserProfileProps;
}

export function UserProvider({ children, initialUser }: UserProviderProps) {
  const { setUser } = useUser();

  useEffect(() => {
    if (initialUser) {
      setUser(initialUser);
    }
  }, [initialUser, setUser]);

  return <>{children}</>;
}
