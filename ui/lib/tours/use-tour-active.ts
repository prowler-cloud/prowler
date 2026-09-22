"use client";

import { useSyncExternalStore } from "react";

// driver.js flags <body> with this class while a tour is driving.
const TOUR_ACTIVE_CLASS = "driver-active";

function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.body, {
    attributes: true,
    attributeFilter: ["class"],
  });
  return () => observer.disconnect();
}

const getSnapshot = () => document.body.classList.contains(TOUR_ACTIVE_CLASS);
const getServerSnapshot = () => false;

/** True while a product tour is on screen, so other callouts can wait their turn. */
export function useTourActive(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}
