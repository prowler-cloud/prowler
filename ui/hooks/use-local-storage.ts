"use client";

import { useEffect, useState } from "react";

export const useLocalStorage = (
  key: string,
  initialValue: string | boolean,
): [
  string | boolean,
  (
    value: string | boolean | ((val: string | boolean) => string | boolean),
  ) => void,
] => {
  const [state, setState] = useState<string | boolean>(initialValue);

  useEffect(() => {
    try {
      const value = window.localStorage.getItem(key);

      if (value) {
        setState(JSON.parse(value));
      }
    } catch (error) {
      console.error(error);
    }
  }, [key]);

  const setValue = (
    value: string | boolean | ((val: string | boolean) => string | boolean),
  ) => {
    try {
      // If the passed value is a callback function,
      //  then call it with the existing state.
      const valueToStore =
        typeof value === "function"
          ? (value as (val: string | boolean) => string | boolean)(state)
          : value;
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
      setState(valueToStore);
    } catch (error) {
      console.error(error);
    }
  };

  return [state, setValue];
};
