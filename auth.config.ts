import bcryptjs from "bcryptjs";
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
        console.log({ email, password }, "from AuthConfig.ts");

        // Check the user using the email

        // const user = await getUser(email);
        // if (!user) return null;

        // Compare passwords

        // if (!bcryptjs.compareSync(password, user.password)) return null;

        // Return the user object without the password field

        // const { password: _, ...rest } = user;
        // return rest;
      },
    }),
  ],
} satisfies NextAuthConfig;

export const { signIn, signOut, auth } = NextAuth(authConfig);
