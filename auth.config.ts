import type { NextAuthConfig } from "next-auth";

export const authConfig = {
  pages: {
    signIn: "/sign-in",
    // signUp: "/sign-up",
  },
  providers: [],
} satisfies NextAuthConfig;
