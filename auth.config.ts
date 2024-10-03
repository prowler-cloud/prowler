import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

import { getToken } from "./actions/auth";

export const authConfig = {
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/sign-in",
    newUser: "/sign-up",
  },

  providers: [
    Credentials({
      name: "credentials",
      credentials: {
        email: { label: "email", type: "text" },
        password: { label: "password", type: "password" },
      },
      async authorize(credentials) {
        const parsedCredentials = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        if (!parsedCredentials.success) return null;

        const user = await getToken(parsedCredentials.data);

        if (!user) return null;

        return user;
      },
    }),
  ],
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith("/");
      const isSignUpPage = nextUrl.pathname === "/sign-up";

      // Allow access to sign-up page
      if (isSignUpPage) return true;

      if (isOnDashboard) {
        if (isLoggedIn) return true;
        return false; // Redirect users who are not logged in to the login page
      } else if (isLoggedIn) {
        return Response.redirect(new URL("/", nextUrl));
      }
      return true;
    },

    jwt: async ({ token, user, account }) => {
      // console.log(`In jwt callback - Token is ${JSON.stringify(token)}`);
      if (user && account) {
        // console.log(`In jwt callback - User is ${JSON.stringify(user)}`);
        // console.log(`In jwt callback - Account is ${JSON.stringify(account)}`);
        // token.data = user;
        return {
          ...token,
          accessToken: user.accessToken,
          refreshToken: user.refreshToken,
          user,
        };
      }
      return token;
    },

    session: async ({ session, token }) => {
      console.log(`In session callback - Token is ${JSON.stringify(token)}`);
      // session.user = token.data as any;
      if (token) {
        session.accessToken = token.accessToken;
        session.refreshToken = token.refreshToken;
      }
      // console.log("session", session);
      return session;
    },
  },
} satisfies NextAuthConfig;

export const { signIn, signOut, auth, handlers } = NextAuth(authConfig);
