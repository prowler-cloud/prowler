export function SessionProvider({ children }: { children: React.ReactNode }) {
  return children;
}
export function useSession() {
  return { data: null, status: "unauthenticated", update: async () => null };
}
export function signIn() {}
export function signOut() {}
