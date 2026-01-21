"use client";

import { LoaderCircleIcon, SearchIcon } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { Input } from "@/components/shadcn/input/input";
import { cn } from "@/lib/utils";

const SEARCH_DEBOUNCE_MS = 300;

interface ClientSideSearchProps {
  value: string;
  onChange: (value: string) => void;
}

export function ClientSideSearch({ value, onChange }: ClientSideSearchProps) {
  const [localValue, setLocalValue] = useState(value);
  const [isLoading, setIsLoading] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const id = useId();
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const shouldStayExpanded = localValue.length > 0 || isFocused;

  useEffect(() => {
    setLocalValue(value);
    if (value) {
      setIsExpanded(true);
    }
  }, [value]);

  const handleChange = (newValue: string) => {
    setLocalValue(newValue);

    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    if (newValue) {
      setIsLoading(true);
      debounceTimeoutRef.current = setTimeout(() => {
        onChange(newValue);
        setIsLoading(false);
      }, SEARCH_DEBOUNCE_MS);
    } else {
      setIsLoading(false);
      onChange("");
    }
  };

  useEffect(() => {
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, []);

  const handleMouseEnter = () => setIsExpanded(true);
  const handleMouseLeave = () => {
    if (!shouldStayExpanded) setIsExpanded(false);
  };
  const handleFocus = () => {
    setIsFocused(true);
    setIsExpanded(true);
  };
  const handleBlur = () => {
    setIsFocused(false);
    if (!localValue) setIsExpanded(false);
  };
  const handleIconClick = () => {
    setIsExpanded(true);
    setTimeout(() => inputRef.current?.focus(), 50);
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
          value={localValue}
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
}
