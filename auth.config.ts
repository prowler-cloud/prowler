import { jwtDecode } from "jwt-decode";
import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

import { getToken } from "./actions/auth";
import { CustomJwtPayload } from "./types";

const refreshAccessToken = async (token: CustomJwtPayload) => {
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/tokens/refresh`);

  const bodyData = {
    data: {
      type: "TokenRefresh",
      attributes: {
        refresh: token.refreshToken,
      },
    },
  };

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
      },
      body: JSON.stringify(bodyData),
    });
    // console.log("response", response);
    const newTokens = await response.json();

    if (!response.ok) {
      // TODO: handle error
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return {
      ...token,
      accessToken: newTokens.data.attributes.access,
      refreshToken: newTokens.data.attributes.refresh,
    };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error refreshing access token:", error);
    return {
      ...token,
      error: "RefreshAccessTokenError",
    };
  }
};

export const authConfig = {
  session: {
    strategy: "jwt",
    // The session will be valid for 24 hours
    maxAge: 24 * 60 * 60,
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
      if (token?.accessToken) {
        const decodedToken = jwtDecode<CustomJwtPayload>(token.accessToken);
        console.log("decodedToken", decodedToken);

        token.accessTokenExpires = decodedToken?.exp * 1000;
      }
      if (user && account) {
        // token.data = user;
        return {
          ...token,
          accessToken: user.accessToken,
          refreshToken: user.refreshToken,
          user,
        };
      }

      console.log(
        "Access token expires",
        token.accessTokenExpires,
        new Date(Number(token.accessTokenExpires)),
      );

      if (Date.now() < token.accessTokenExpires) return token;

      // Access token is expired, we need to refresh it
      return refreshAccessToken(token);
    },

    session: async ({ session, token }) => {
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
