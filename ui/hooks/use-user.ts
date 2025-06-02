import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import { UserProfileProps } from "@/types";

type UserStore = {
  user: UserProfileProps | null;
  setUser: (user: UserProfileProps | null) => void;
  clearUser: () => void;
};

export const useUser = create(
  persist<UserStore>(
    (set) => ({
      user: null,
      setUser: (user: UserProfileProps | null) => {
        set({ user });
      },
      clearUser: () => {
        set({ user: null });
      },
    }),
    {
      name: "user-store",
      storage: createJSONStorage(() => localStorage),
    },
  ),
);
