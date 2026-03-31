export default function NextAuth() {
  return {
    signIn: async () => {},
    signOut: async () => {},
    auth: async () => null,
    handlers: { GET: () => {}, POST: () => {} },
  };
}

export type NextAuthConfig = Record<string, unknown>;
export type DefaultSession = Record<string, unknown>;
export type Session = Record<string, unknown>;
export type User = Record<string, unknown>;
