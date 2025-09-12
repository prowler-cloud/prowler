import { DefaultSession } from "next-auth";

import { RolePermissionAttributes } from "./types/users";

declare module "next-auth" {
  interface User extends NextAuthUser {
    name: string;
    email: string;
    company?: string;
    dateJoined: string;
    permissions?: RolePermissionAttributes;
  }

  interface Session extends DefaultSession {
    user: {
      name: string;
      email: string;
      companyName?: string;
      dateJoined: string;
      permissions: RolePermissionAttributes;
    } & DefaultSession["user"];
    userId: string;
    tenantId: string;
    accessToken: string;
    refreshToken: string;
  }
}
