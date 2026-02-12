"use client";

import { useSearchParams } from "next/navigation";
import {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useState,
} from "react";

interface FilterTransitionContextType {
  isPending: boolean;
  signalFilterChange: () => void;
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

/**
 * Provides a shared pending state for filter changes.
 *
 * Filter components signal the start of navigation via signalFilterChange(),
 * and use their own local useTransition() for the actual router.push().
 * This avoids a known Next.js production bug where a shared useTransition()
 * wrapping router.push() causes the navigation to be silently reverted.
 *
 * The pending state auto-resets when searchParams change (navigation completed).
 */
export const FilterTransitionProvider = ({
  children,
}: FilterTransitionProviderProps) => {
  const searchParams = useSearchParams();
  const [isPending, setIsPending] = useState(false);

  // Auto-reset pending state when searchParams change (navigation completed)
  useEffect(() => {
    setIsPending(false);
  }, [searchParams]);

  const signalFilterChange = () => {
    setIsPending(true);
  };

  return (
    <FilterTransitionContext.Provider value={{ isPending, signalFilterChange }}>
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
