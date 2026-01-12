import type { DefaultSession, User as NextAuthUser } from "next-auth";

import { RolePermissionAttributes } from "./types/users";

declare module "next-auth" {
  interface User extends NextAuthUser {
    name: string;
    email: string;
    company?: string;
    dateJoined: string;
    permissions?: RolePermissionAttributes;
  }

  type SessionUser = NonNullable<DefaultSession["user"]> & {
    companyName?: string;
    dateJoined?: string;
    permissions: RolePermissionAttributes;
  };

  interface Session extends DefaultSession {
    user?: SessionUser;
    userId?: string;
    tenantId?: string;
    accessToken?: string;
    refreshToken?: string;
    error?: string;
  }
}
