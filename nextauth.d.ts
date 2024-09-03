import { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      tenantId: string;
      firstName: string;
      companyName: string;
      email: string;
      role: string;
      image?: string;
    } & DefaultSession["user"];
  }
}
