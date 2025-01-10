import { jwtDecode, JwtPayload } from "jwt-decode";
import NextAuth, { type NextAuthConfig, User } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

import { getToken, getUserByMe } from "./actions/auth";

interface CustomJwtPayload extends JwtPayload {
  user_id: string;
  tenant_id: string;
}

const refreshAccessToken = async (token: JwtPayload) => {
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/tokens/refresh`);

  const bodyData = {
    data: {
      type: "tokens-refresh",
      attributes: {
        refresh: (token as any).refreshToken,
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
    const newTokens = await response.json();

    if (!response.ok) {
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
            password: z.string().min(12),
          })
          .safeParse(credentials);

        if (!parsedCredentials.success) return null;

        const tokenResponse = await getToken(parsedCredentials.data);
        if (!tokenResponse) return null;

        const userMeResponse = await getUserByMe(tokenResponse.accessToken);

        const user = {
          name: userMeResponse.name,
          email: userMeResponse.email,
          company: userMeResponse?.company,
          dateJoined: userMeResponse.dateJoined,
        };

        return {
          ...user,
          accessToken: tokenResponse.accessToken,
          refreshToken: tokenResponse.refreshToken,
        };
      },
    }),
  ],
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith("/");
      const isSignUpPage = nextUrl.pathname === "/sign-up";
      //CLOUD API CHANGES

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

    jwt: async ({ token, account, user }) => {
      if (token?.accessToken) {
        const decodedToken = jwtDecode(
          token.accessToken as string,
        ) as CustomJwtPayload;
        // eslint-disable-next-line no-console
        // console.log("decodedToken", decodedToken);
        token.accessTokenExpires = (decodedToken.exp as number) * 1000;
        token.user_id = decodedToken.user_id;
        token.tenant_id = decodedToken.tenant_id;
      }

      const userInfo = {
        name: user?.name,
        companyName: user?.company,
        email: user?.email,
        dateJoined: user?.dateJoined,
      };

      if (account && user) {
        return {
          ...token,
          userId: token.user_id,
          tenantId: token.tenant_id,
          accessToken: (user as User & { accessToken: JwtPayload }).accessToken,
          refreshToken: (user as User & { refreshToken: JwtPayload })
            .refreshToken,
          user: userInfo,
        };
      }

      // eslint-disable-next-line no-console
      // console.log(
      //   "Access token expires",
      //   token.accessTokenExpires,
      //   new Date(Number(token.accessTokenExpires)),
      // );

      // If the access token is not expired, return the token
      if (
        typeof token.accessTokenExpires === "number" &&
        Date.now() < token.accessTokenExpires
      )
        return token;

      // If the access token is expired, try to refresh it
      return refreshAccessToken(token as JwtPayload);
    },

    session: async ({ session, token }) => {
      if (token) {
        session.userId = token?.user_id as string;
        session.tenantId = token?.tenant_id as string;
        session.accessToken = token?.accessToken as string;
        session.refreshToken = token?.refreshToken as string;
        session.user = token.user as any;
      }

      // console.log("session", session);
      return session;
    },
  },
} satisfies NextAuthConfig;

export const { signIn, signOut, auth, handlers } = NextAuth(authConfig);
