"use client";

import { LoaderCircleIcon, SearchIcon } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";

import { Input } from "@/components/shadcn/input/input";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { cn } from "@/lib/utils";

const SEARCH_DEBOUNCE_MS = 500;

interface DataTableSearchProps {
  /** Prefix for URL params to avoid conflicts (e.g., "findings" -> "findingsSearch") */
  paramPrefix?: string;

  /*
   * Controlled mode: Use these props to manage search via React state
   * instead of URL params. Useful for tables in drawers/modals to avoid
   * triggering page re-renders when searching.
   */
  controlledValue?: string;
  onSearchChange?: (value: string) => void;
}

export const DataTableSearch = ({
  paramPrefix = "",
  controlledValue,
  onSearchChange,
}: DataTableSearchProps) => {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const { updateFilter } = useUrlFilters();
  const [internalValue, setInternalValue] = useState("");
  // In controlled mode, track display value separately for immediate feedback
  const [displayValue, setDisplayValue] = useState(controlledValue ?? "");
  const [isLoading, setIsLoading] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const id = useId();
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Use controlled value if provided, otherwise internal state
  const isControlled = controlledValue !== undefined && onSearchChange;
  // For display: use displayValue in controlled mode (for responsive typing), internalValue otherwise
  const value = isControlled ? displayValue : internalValue;

  // Sync displayValue when controlledValue changes externally (e.g., clear filters)
  useEffect(() => {
    if (isControlled) {
      setDisplayValue(controlledValue);
    }
  }, [controlledValue, isControlled]);

  // Determine param names based on prefix
  const searchParam = paramPrefix ? `${paramPrefix}Search` : "filter[search]";
  const pageParam = paramPrefix ? `${paramPrefix}Page` : "page";

  // Keep expanded if there's a value or input is focused
  const shouldStayExpanded = value.length > 0 || isFocused;

  // Sync with URL on mount (only for uncontrolled mode)
  useEffect(() => {
    if (isControlled) return;
    const searchFromUrl = searchParams.get(searchParam) || "";
    setInternalValue(searchFromUrl);
    // If there's a search value, start expanded
    if (searchFromUrl) {
      setIsExpanded(true);
    }
  }, [searchParams, searchParam, isControlled]);

  // Handle input change with debounce
  const handleChange = (newValue: string) => {
    // For controlled mode, update display immediately, debounce the callback
    if (isControlled) {
      // Update display value immediately for responsive typing
      setDisplayValue(newValue);

      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }

      setIsLoading(true);
      debounceTimeoutRef.current = setTimeout(() => {
        onSearchChange(newValue);
        setIsLoading(false);
      }, SEARCH_DEBOUNCE_MS);
      return;
    }

    setInternalValue(newValue);

    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    // If using prefix, handle URL updates directly instead of useUrlFilters
    if (paramPrefix) {
      setIsLoading(true);
      debounceTimeoutRef.current = setTimeout(() => {
        const params = new URLSearchParams(searchParams.toString());
        if (newValue) {
          params.set(searchParam, newValue);
        } else {
          params.delete(searchParam);
        }
        params.set(pageParam, "1"); // Reset to first page
        router.push(`${pathname}?${params.toString()}`, { scroll: false });
        setIsLoading(false);
      }, SEARCH_DEBOUNCE_MS);
    } else {
      // Original behavior for non-prefixed search
      if (newValue) {
        setIsLoading(true);
        debounceTimeoutRef.current = setTimeout(() => {
          updateFilter("search", newValue);
          setIsLoading(false);
        }, SEARCH_DEBOUNCE_MS);
      } else {
        setIsLoading(false);
        updateFilter("search", null);
      }
    }
  };

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, []);

  const handleMouseEnter = () => {
    setIsExpanded(true);
  };

  const handleMouseLeave = () => {
    if (!shouldStayExpanded) {
      setIsExpanded(false);
    }
  };

  const handleFocus = () => {
    setIsFocused(true);
    setIsExpanded(true);
  };

  const handleBlur = () => {
    setIsFocused(false);
    if (!value) {
      setIsExpanded(false);
    }
  };

  const handleIconClick = () => {
    setIsExpanded(true);
    // Focus input after expansion animation starts
    setTimeout(() => {
      inputRef.current?.focus();
    }, 50);
  };

  return (
    <div
      className={cn(
        "relative flex items-center transition-all duration-300 ease-in-out",
        isExpanded ? "w-64" : "w-10",
      )}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      {/* Collapsed state - just icon button */}
      <button
        type="button"
        onClick={handleIconClick}
        className={cn(
          "border-border-neutral-tertiary bg-bg-neutral-tertiary absolute left-0 flex size-10 items-center justify-center rounded-md border transition-opacity duration-200",
          isExpanded ? "pointer-events-none opacity-0" : "opacity-100",
        )}
        aria-label="Open search"
      >
        <SearchIcon className="text-text-neutral-tertiary size-4" />
      </button>

      {/* Expanded state - full input */}
      <div
        className={cn(
          "relative w-full transition-opacity duration-200",
          isExpanded ? "opacity-100" : "pointer-events-none opacity-0",
        )}
      >
        <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
          <SearchIcon className="text-text-neutral-tertiary size-4" />
        </div>
        <Input
          ref={inputRef}
          id={id}
          type="search"
          placeholder="Search..."
          value={value}
          onChange={(e) => handleChange(e.target.value)}
          onFocus={handleFocus}
          onBlur={handleBlur}
          className="border-border-neutral-tertiary bg-bg-neutral-tertiary focus:border-border-input-primary-pressed pr-9 pl-9 focus:ring-0 focus:ring-offset-0 [&::-webkit-search-cancel-button]:appearance-none [&::-webkit-search-decoration]:appearance-none [&::-webkit-search-results-button]:appearance-none [&::-webkit-search-results-decoration]:appearance-none"
        />
        {isLoading && (
          <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
            <LoaderCircleIcon className="text-text-neutral-tertiary size-4 animate-spin" />
          </div>
        )}
      </div>
    </div>
  );
};
