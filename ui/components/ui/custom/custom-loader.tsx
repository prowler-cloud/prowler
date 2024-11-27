"use client";

import { useEffect, useState } from "react";

export const CustomLoader = (props: { size?: "small" }) => {
  const [loadingSpinner, setloadingSpinner] = useState(0);
  const loadingChars = "|/-\\";

  const textClasses = `w-xs px-xs ${props.size === "small" ? "!text-s" : ""}`;

  useEffect(() => {
    setTimeout(() => setloadingSpinner(loadingSpinner + 1), 150);
  }, [loadingSpinner]);

  return <p className={textClasses}>{loadingChars[loadingSpinner % 4]}</p>;
};
