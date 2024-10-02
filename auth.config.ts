import bcryptjs from "bcryptjs";
import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";

import { userMockData } from "./lib";

// const key = new TextEncoder().encode(process.env.AUTH_SECRET);
// const SALT_ROUNDS = 10;

// export async function hashPassword(password: string) {
//   return hash(password, SALT_ROUNDS);
// }

async function getUser(email: string, password: string): Promise<any | null> {
  // Check if the user exists in the userMockData array.
  const user = userMockData.find((user) => user.email === email);
  if (!user) return null;

  if (!bcryptjs.compareSync(password, user.password)) return null;

  return {
    id: user.id,
    tenantId: user.tenantId,
    name: user.name,
    companyName: user.companyName,
    email: user.email,
    role: user.role,
    image: user.image,
  };
}

export const authConfig = {
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/sign-in",
    newUser: "/sign-up",
  },
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith("/");
      const isSignUpPage = nextUrl.pathname === "/sign-up";

      // Permitir acceso a /sign-up incluso si no está autenticado
      if (isSignUpPage) return true;

      if (isOnDashboard) {
        if (isLoggedIn) return true;
        return false; // Redirigir usuarios no autenticados a la página de login
      } else if (isLoggedIn) {
        return Response.redirect(new URL("/", nextUrl));
      }
      return true;
    },

    jwt({ token, user }) {
      if (user) {
        token.data = user;
      }
      return token;
    },

    session({ session, token }) {
      session.user = token.data as any;
      return session;
    },
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

        if (!parsedCredentials.success) {
          return null;
        }
        const { email, password } = parsedCredentials.data;
        console.log("email", email);
        console.log("password", password);

        const user = await getUser(email, password);
        if (!user) return null;
        return user;
      },
    }),
  ],
} satisfies NextAuthConfig;

export const { signIn, signOut, auth, handlers } = NextAuth(authConfig);
