"use client";

import { LoaderCircleIcon, SearchIcon, X } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Input } from "@/components/shadcn/input/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
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
  placeholder?: string;
  /** Badge shown inside the search input (e.g., active drill-down group title) */
  badge?: { label: string; onDismiss: () => void };
}

export const DataTableSearch = ({
  paramPrefix = "",
  controlledValue,
  onSearchChange,
  placeholder = "Search...",
  badge,
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

  // Force expanded when badge is present
  const hasBadge = !!badge;

  // Sync displayValue when controlledValue changes externally (e.g., clear filters)
  useEffect(() => {
    if (isControlled) {
      setDisplayValue(controlledValue);
    }
  }, [controlledValue, isControlled]);

  // Determine param names based on prefix
  const searchParam = paramPrefix ? `${paramPrefix}Search` : "filter[search]";
  const pageParam = paramPrefix ? `${paramPrefix}Page` : "page";

  // Keep expanded if there's a value or input is focused or badge is present
  const shouldStayExpanded = value.length > 0 || isFocused || hasBadge;

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
    if (!value && !hasBadge) {
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

  const effectiveExpanded = isExpanded || hasBadge;

  return (
    <div
      className={cn(
        "relative flex items-center transition-all duration-300 ease-in-out",
        effectiveExpanded ? (hasBadge ? "w-[28rem]" : "w-64") : "w-10",
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
          effectiveExpanded ? "pointer-events-none opacity-0" : "opacity-100",
        )}
        aria-label="Open search"
      >
        <SearchIcon className="text-text-neutral-tertiary size-4" />
      </button>

      {/* Expanded state - full input with optional badge */}
      <div
        className={cn(
          "relative w-full transition-opacity duration-200",
          effectiveExpanded ? "opacity-100" : "pointer-events-none opacity-0",
        )}
      >
        <div
          className={cn(
            "border-border-neutral-tertiary bg-bg-neutral-tertiary hover:bg-bg-neutral-secondary flex items-center gap-1.5 rounded-md border transition-colors",
            isFocused && "border-border-input-primary-pressed",
          )}
        >
          <div className="flex shrink-0 items-center pl-3">
            <SearchIcon className="text-text-neutral-tertiary size-4" />
          </div>

          {hasBadge && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge
                  variant="tag"
                  className="max-w-[200px] shrink-0 cursor-default gap-1 truncate"
                >
                  <span className="truncate">{badge.label}</span>
                  <button
                    type="button"
                    aria-label="Dismiss filter"
                    className="hover:text-text-neutral-primary ml-0.5 shrink-0"
                    onClick={(e) => {
                      e.stopPropagation();
                      badge.onDismiss();
                    }}
                  >
                    <X className="size-3" />
                  </button>
                </Badge>
              </TooltipTrigger>
              <TooltipContent>{badge.label}</TooltipContent>
            </Tooltip>
          )}

          <Input
            ref={inputRef}
            id={id}
            type="search"
            placeholder={placeholder}
            value={value}
            onChange={(e) => handleChange(e.target.value)}
            onFocus={handleFocus}
            onBlur={handleBlur}
            className="h-9 min-w-0 flex-1 border-0 bg-transparent pr-9 shadow-none hover:bg-transparent focus:border-0 focus:ring-0 focus:ring-offset-0 focus-visible:ring-0 [&::-webkit-search-cancel-button]:appearance-none [&::-webkit-search-decoration]:appearance-none [&::-webkit-search-results-button]:appearance-none [&::-webkit-search-results-decoration]:appearance-none"
          />

          {isLoading && (
            <div className="flex shrink-0 items-center pr-3">
              <LoaderCircleIcon className="text-text-neutral-tertiary size-4 animate-spin" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
