import { jwtDecode, type JwtPayload } from "jwt-decode";
import { NextResponse } from "next/server";
import NextAuth, {
  type DefaultSession,
  type NextAuthConfig,
  type Session,
  User,
} from "next-auth";
import type { JWT } from "next-auth/jwt";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

import { getToken, getUserByMe } from "./actions/auth";
import { apiBaseUrl } from "./lib";
import type { RolePermissionAttributes } from "./types/users";

interface CustomJwtPayload extends JwtPayload {
  user_id: string;
  tenant_id: string;
}

type DefaultSessionUser = NonNullable<DefaultSession["user"]>;

type TokenUser = DefaultSessionUser & {
  companyName?: string;
  dateJoined?: string;
  permissions: RolePermissionAttributes;
};

type AuthToken = JWT & {
  accessToken?: string;
  refreshToken?: string;
  accessTokenExpires?: number;
  user_id?: string;
  tenant_id?: string;
  user?: TokenUser;
  error?: string;
};

type ExtendedSession = Session & {
  user?: TokenUser;
  userId?: string;
  tenantId?: string;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
};

const DEFAULT_PERMISSIONS: RolePermissionAttributes = {
  manage_users: false,
  manage_account: false,
  manage_providers: false,
  manage_scans: false,
  manage_integrations: false,
  manage_billing: false,
  unlimited_visibility: false,
};

type TokenUserInput = Partial<TokenUser> & { company?: string };

const toTokenUser = (user?: TokenUserInput): TokenUser =>
  ({
    name: user?.name ?? undefined,
    email: user?.email ?? undefined,
    companyName: user?.companyName ?? user?.company,
    dateJoined: user?.dateJoined,
    permissions: user?.permissions ?? { ...DEFAULT_PERMISSIONS },
  }) as TokenUser;

type UserMeResponse = Awaited<ReturnType<typeof getUserByMe>>;

const tokenUserFromApi = (user: UserMeResponse) =>
  toTokenUser({
    name: user.name,
    email: user.email,
    companyName: user.company,
    dateJoined: user.dateJoined,
    permissions: user.permissions,
  });

const applyDecodedClaims = (
  target: AuthToken,
  accessToken?: string,
  logContext = "access token",
) => {
  if (!accessToken) return;

  try {
    const decodedToken = jwtDecode<CustomJwtPayload>(accessToken);
    target.accessTokenExpires = decodedToken.exp
      ? decodedToken.exp * 1000
      : target.accessTokenExpires;
    target.user_id = decodedToken.user_id ?? target.user_id;
    target.tenant_id = decodedToken.tenant_id ?? target.tenant_id;
  } catch (decodeError) {
    // eslint-disable-next-line no-console
    console.warn(`Unable to decode ${logContext}`, decodeError);
  }
};

const refreshTokenPromises = new Map<string, Promise<AuthToken>>();

const refreshAccessToken = async (token: AuthToken): Promise<AuthToken> => {
  const refreshToken = token.refreshToken;

  if (!refreshToken) {
    return {
      ...token,
      error: "MissingRefreshToken",
    };
  }

  const existingPromise = refreshTokenPromises.get(refreshToken);

  if (existingPromise) {
    return existingPromise;
  }

  const url = new URL(`${apiBaseUrl}/tokens/refresh`);

  const bodyData = {
    data: {
      type: "tokens-refresh",
      attributes: {
        refresh: refreshToken,
      },
    },
  };

  const refreshPromise = (async () => {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/vnd.api+json",
          Accept: "application/vnd.api+json",
        },
        body: JSON.stringify(bodyData),
      });

      const payload = await response.json().catch(() => undefined);

      if (!response.ok) {
        const detail = payload?.errors?.[0]?.detail;
        // eslint-disable-next-line no-console
        console.warn(
          "Failed to refresh access token:",
          detail || `HTTP error ${response.status}`,
        );
        return {
          ...token,
          error: "RefreshAccessTokenError",
        };
      }

      const newAccessToken = payload?.data?.attributes?.access as
        | string
        | undefined;
      const nextRefreshToken =
        (payload?.data?.attributes?.refresh as string | undefined) ??
        refreshToken;

      if (!newAccessToken) {
        // eslint-disable-next-line no-console
        console.warn("Missing access token in refresh response");
        return {
          ...token,
          error: "RefreshAccessTokenError",
        };
      }

      const nextToken: AuthToken = {
        ...token,
        accessToken: newAccessToken,
        refreshToken: nextRefreshToken,
        error: undefined,
      };

      applyDecodedClaims(nextToken, newAccessToken, "refreshed access token");

      return nextToken;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.warn("Error refreshing access token:", error);
      return {
        ...token,
        error: "RefreshAccessTokenError",
      };
    }
  })();

  refreshTokenPromises.set(refreshToken, refreshPromise);

  try {
    return await refreshPromise;
  } finally {
    refreshTokenPromises.delete(refreshToken);
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
            email: z.email(),
            password: z.string().min(12),
          })
          .safeParse(credentials);

        if (!parsedCredentials.success) return null;

        const { email, password } = parsedCredentials.data;
        const tokenResponse = await getToken({
          email,
          password,
        });
        if (!tokenResponse) return null;

        const userMeResponse = await getUserByMe(tokenResponse.accessToken);

        const user = tokenUserFromApi(userMeResponse);

        return {
          ...user,
          accessToken: tokenResponse.accessToken,
          refreshToken: tokenResponse.refreshToken,
        };
      },
    }),
    Credentials({
      id: "social-oauth",
      name: "social-oauth",
      credentials: {
        accessToken: { label: "Access Token", type: "text" },
        refreshToken: { label: "Refresh Token", type: "text" },
      },
      async authorize(credentials) {
        const accessToken = credentials?.accessToken;

        if (!accessToken) {
          return null;
        }

        try {
          const userMeResponse = await getUserByMe(accessToken as string);

          const user = tokenUserFromApi(userMeResponse);

          return {
            ...user,
            accessToken: credentials.accessToken,
            refreshToken: credentials.refreshToken,
          };
        } catch (error) {
          console.error("Error in authorize:", error);
          return null;
        }
      },
    }),
  ],
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const sessionError = auth?.error;
      const isSignUpPage = nextUrl.pathname === "/sign-up";
      const isSignInPage = nextUrl.pathname === "/sign-in";

      // Allow access to sign-up and sign-in pages
      if (isSignUpPage || isSignInPage) return true;

      // For all other routes, require authentication
      // Return NextResponse.redirect to preserve callbackUrl for post-login redirect
      if (!isLoggedIn) {
        const signInUrl = new URL("/sign-in", nextUrl.origin);
        signInUrl.searchParams.set("callbackUrl", nextUrl.pathname);
        // Include session error if present (e.g., RefreshAccessTokenError)
        if (sessionError) {
          signInUrl.searchParams.set("error", sessionError);
        }
        return NextResponse.redirect(signInUrl);
      }

      return true;
    },

    jwt: async ({ token, account, user }) => {
      const authToken = token as AuthToken;

      applyDecodedClaims(authToken, authToken.accessToken);

      if (account && user) {
        const signedInUser = user as User &
          TokenUserInput & {
            accessToken: string;
            refreshToken: string;
          };

        const nextAuthToken: AuthToken = {
          ...authToken,
          accessToken: signedInUser.accessToken,
          refreshToken: signedInUser.refreshToken,
          user: toTokenUser(signedInUser),
          error: undefined,
        };

        applyDecodedClaims(
          nextAuthToken,
          signedInUser.accessToken,
          "access token on sign-in",
        );

        return nextAuthToken;
      }

      if (
        typeof authToken.accessTokenExpires === "number" &&
        Date.now() < authToken.accessTokenExpires
      ) {
        return authToken;
      }

      return refreshAccessToken(authToken);
    },

    session: async ({ session, token }) => {
      const authToken = token as AuthToken;
      const nextSession = { ...session } as ExtendedSession;

      if (authToken?.error) {
        nextSession.error = authToken.error;
        nextSession.user = undefined;
        nextSession.userId = undefined;
        nextSession.tenantId = undefined;
        nextSession.accessToken = undefined;
        nextSession.refreshToken = undefined;
        return nextSession;
      }

      nextSession.error = undefined;
      nextSession.userId = authToken.user_id ?? nextSession.userId;
      nextSession.tenantId = authToken.tenant_id ?? nextSession.tenantId;
      nextSession.accessToken =
        authToken.accessToken ?? nextSession.accessToken;
      nextSession.refreshToken =
        authToken.refreshToken ?? nextSession.refreshToken;
      nextSession.user = authToken.user ?? nextSession.user;

      return nextSession;
    },
  },
} satisfies NextAuthConfig;

export const { signIn, signOut, auth, handlers } = NextAuth(authConfig);
