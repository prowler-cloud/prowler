import { jwtDecode, type JwtPayload } from "jwt-decode";
import { NextResponse } from "next/server";
import NextAuth, {
  type DefaultSession,
  type NextAuthConfig,
  type Session,
} from "next-auth";
import type { JWT } from "next-auth/jwt";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

import { getToken, getUserByMe } from "./actions/auth";
import { apiBaseUrl } from "./lib";
import type { RolePermissionAttributes } from "./types/users";

interface CustomJwtPayload extends JwtPayload {
  user_id?: string; // Optional - doesn't actually exist in JWT tokens
  sub: string; // Standard JWT subject field - contains the actual user ID
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
  manage_alerts: false,
  unlimited_visibility: false,
};

const TENANT_SWITCH_ERROR = "TenantSwitchError";

type TokenUserInput = Partial<TokenUser> & { company?: string };

type JwtCallback = NonNullable<NonNullable<NextAuthConfig["callbacks"]>["jwt"]>;
type JwtCallbackParams = Parameters<JwtCallback>[0];

interface JwtCallbackCredentials {
  accessToken?: string;
  refreshToken?: string;
}

type AuthJwtUser = JwtCallbackParams["user"] &
  TokenUserInput &
  JwtCallbackCredentials;

interface AuthJwtCallbackParams
  extends Omit<JwtCallbackParams, "session" | "token" | "user"> {
  session?: Partial<ExtendedSession>;
  token: AuthToken;
  user: AuthJwtUser;
}

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
    // Map standard JWT "sub" field to user_id
    target.user_id = decodedToken.sub ?? target.user_id;
    target.tenant_id = decodedToken.tenant_id ?? target.tenant_id;
  } catch (decodeError) {
    // eslint-disable-next-line no-console
    console.warn(`Unable to decode ${logContext}`, decodeError);
  }
};

interface RotatedCredentials {
  accessToken: string;
  refreshToken: string;
}

type RefreshOutcome =
  | { status: "rotated"; credentials: RotatedCredentials }
  | { status: "failed" };

/**
 * The API rotates refresh tokens and blacklists the previous one
 * (ROTATE_REFRESH_TOKENS + BLACKLIST_AFTER_ROTATION), while NextAuth can only
 * persist the resulting cookie where Set-Cookie is allowed — the proxy, Route
 * Handlers and Server Actions, never a Server Component render. A refresh
 * performed outside those contexts therefore consumes the stored refresh token
 * without saving its replacement, and the next request replays a blacklisted
 * token and looks like an expired session.
 *
 * Keeping the rotated pair keyed by the token that produced it lets any request
 * still carrying the stale cookie reuse the replacement instead. The cache is
 * per-process, so it narrows the window rather than closing it across replicas.
 */
const ROTATED_CREDENTIALS_TTL_MS = 60 * 1000;

interface RefreshCacheEntry {
  outcome: Promise<RefreshOutcome>;
  expiresAt: number;
}

const refreshOutcomes = new Map<string, RefreshCacheEntry>();

const readPendingOutcome = (
  refreshToken: string,
): Promise<RefreshOutcome> | undefined => {
  const entry = refreshOutcomes.get(refreshToken);

  if (!entry) return undefined;

  if (Date.now() >= entry.expiresAt) {
    refreshOutcomes.delete(refreshToken);
    return undefined;
  }

  return entry.outcome;
};

const requestRotatedCredentials = async (
  refreshToken: string,
): Promise<RefreshOutcome> => {
  const url = new URL(`${apiBaseUrl}/tokens/refresh`);

  const bodyData = {
    data: {
      type: "tokens-refresh",
      attributes: {
        refresh: refreshToken,
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

    const payload = await response.json().catch(() => undefined);

    if (!response.ok) {
      const detail = payload?.errors?.[0]?.detail;
      // eslint-disable-next-line no-console
      console.warn(
        "Failed to refresh access token:",
        detail || `HTTP error ${response.status}`,
      );
      return { status: "failed" };
    }

    const newAccessToken = payload?.data?.attributes?.access as
      | string
      | undefined;

    if (!newAccessToken) {
      // eslint-disable-next-line no-console
      console.warn("Missing access token in refresh response");
      return { status: "failed" };
    }

    const nextRefreshToken =
      (payload?.data?.attributes?.refresh as string | undefined) ??
      refreshToken;

    return {
      status: "rotated",
      credentials: {
        accessToken: newAccessToken,
        refreshToken: nextRefreshToken,
      },
    };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.warn("Error refreshing access token:", error);
    return { status: "failed" };
  }
};

const refreshAccessToken = async (token: AuthToken): Promise<AuthToken> => {
  const refreshToken = token.refreshToken;

  if (!refreshToken) {
    return {
      ...token,
      error: "MissingRefreshToken",
    };
  }

  let pendingOutcome = readPendingOutcome(refreshToken);

  if (!pendingOutcome) {
    pendingOutcome = requestRotatedCredentials(refreshToken);
    const entry: RefreshCacheEntry = {
      outcome: pendingOutcome,
      // In-flight requests must always dedupe; the real expiry is set once the
      // rotated pair is known.
      expiresAt: Number.POSITIVE_INFINITY,
    };
    refreshOutcomes.set(refreshToken, entry);

    void pendingOutcome.then((outcome) => {
      if (outcome.status === "failed") {
        // A failure must not be cached: the next attempt has to reach the API.
        refreshOutcomes.delete(refreshToken);
        return;
      }

      entry.expiresAt = Date.now() + ROTATED_CREDENTIALS_TTL_MS;
    });
  }

  const outcome = await pendingOutcome;

  if (outcome.status === "failed") {
    return {
      ...token,
      error: "RefreshAccessTokenError",
    };
  }

  const nextToken: AuthToken = {
    ...token,
    accessToken: outcome.credentials.accessToken,
    refreshToken: outcome.credentials.refreshToken,
    error: undefined,
  };

  applyDecodedClaims(
    nextToken,
    outcome.credentials.accessToken,
    "refreshed access token",
  );

  return nextToken;
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
      const isInvitationPage =
        nextUrl.pathname.startsWith("/invitation/accept");

      // Allow access to sign-up, sign-in, and invitation pages
      if (isSignUpPage || isSignInPage || isInvitationPage) return true;

      // For all other routes, require authentication
      // Return NextResponse.redirect to preserve callbackUrl for post-login redirect
      if (!isLoggedIn) {
        const signInUrl = new URL("/sign-in", nextUrl.origin);
        signInUrl.searchParams.set(
          "callbackUrl",
          nextUrl.pathname + nextUrl.search,
        );
        // Include session error if present (e.g., RefreshAccessTokenError)
        if (sessionError) {
          signInUrl.searchParams.set("error", sessionError);
        }
        return NextResponse.redirect(signInUrl);
      }

      return true;
    },

    jwt: async ({
      token: authToken,
      account,
      user,
      trigger,
      session,
    }: AuthJwtCallbackParams): Promise<AuthToken> => {
      // Handle tenant switch: update tokens from client-side useSession().update()
      if (trigger === "update" && session?.accessToken) {
        const newAccessToken = session.accessToken;

        try {
          const userMeResponse = await getUserByMe(newAccessToken);
          const nextAuthToken: AuthToken = {
            ...authToken,
            accessToken: newAccessToken,
            refreshToken: session.refreshToken,
            user: tokenUserFromApi(userMeResponse),
            error: undefined,
          };

          applyDecodedClaims(nextAuthToken, newAccessToken, "tenant switch");

          return nextAuthToken;
        } catch (error) {
          // eslint-disable-next-line no-console
          console.warn("Error refreshing user after tenant switch:", error);
          return {
            ...authToken,
            error: TENANT_SWITCH_ERROR,
          };
        }
      }

      applyDecodedClaims(authToken, authToken.accessToken);

      if (account && user?.accessToken && user.refreshToken) {
        const nextAuthToken: AuthToken = {
          ...authToken,
          accessToken: user.accessToken,
          refreshToken: user.refreshToken,
          user: toTokenUser(user),
          error: undefined,
        };

        applyDecodedClaims(
          nextAuthToken,
          user.accessToken,
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

      if (authToken.error && authToken.error !== TENANT_SWITCH_ERROR) {
        nextSession.error = authToken.error;
        nextSession.user = undefined;
        nextSession.userId = undefined;
        nextSession.tenantId = undefined;
        nextSession.accessToken = undefined;
        nextSession.refreshToken = undefined;
        return nextSession;
      }

      nextSession.error = authToken.error;
      authToken.error = undefined;
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
