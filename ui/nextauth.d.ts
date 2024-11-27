import { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface User extends NextAuthUser {
    name: string;
    email: string;
    company?: string;
    dateJoined: string;
  }

  interface Session extends DefaultSession {
    user: {
      name: string;
      email: string;
      companyName?: string;
      dateJoined: string;
    } & DefaultSession["user"];
    userId: string;
    tenantId: string;
    accessToken: string;
    refreshToken: string;
  }
}
