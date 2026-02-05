"use client";

import {
  createContext,
  ReactNode,
  TransitionStartFunction,
  useContext,
  useTransition,
} from "react";

interface FilterTransitionContextType {
  isPending: boolean;
  startTransition: TransitionStartFunction;
}

const FilterTransitionContext = createContext<
  FilterTransitionContextType | undefined
>(undefined);

export const useFilterTransition = () => {
  const context = useContext(FilterTransitionContext);
  if (!context) {
    throw new Error(
      "useFilterTransition must be used within a FilterTransitionProvider",
    );
  }
  return context;
};

/**
 * Optional hook that returns undefined if not within a provider.
 * Useful for components that may or may not be within a provider.
 */
export const useFilterTransitionOptional = () => {
  return useContext(FilterTransitionContext);
};

interface FilterTransitionProviderProps {
  children: ReactNode;
}

export const FilterTransitionProvider = ({
  children,
}: FilterTransitionProviderProps) => {
  const [isPending, startTransition] = useTransition();

  return (
    <FilterTransitionContext.Provider value={{ isPending, startTransition }}>
      {children}
    </FilterTransitionContext.Provider>
  );
};

/**
 * Convenience wrapper that provides filter transition context.
 * Use this in pages to enable coordinated loading states across
 * all filter components and the DataTable.
 */
export const FilterTransitionWrapper = ({
  children,
}: FilterTransitionProviderProps) => {
  return <FilterTransitionProvider>{children}</FilterTransitionProvider>;
};
