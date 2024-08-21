import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

export const authConfig = {
  pages: {
    signIn: "/sign-in",
    newUser: "/sign-up",
  },
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsedCredentials.success) return null;

        const { email, password } = parsedCredentials.data;
        console.log("AuthConfig.ts");
        console.log({ email, password });
        return null;
      },
    }),
  ],
} satisfies NextAuthConfig;

export const { signIn, signOut, auth } = NextAuth(authConfig);
