import posthog from "posthog-js";

// Type definitions for tracking payloads
export interface UserLoginPayload {
  email: string;
}

export interface UserRegistrationPayload {
  email: string;
  firstName?: string;
  lastName?: string;
  company?: string;
  fullName?: string;
}

export interface CloudConnectionPayload {
  providerType: string;
  providerAlias: string;
  scanType: "single" | "scheduled";
}

// Initialize a new PostHog session
export const initializeSession = (): void => {
  try {
    posthog.reset(true);
  } catch (error) {
    console.error("Failed to initialize PostHog session:", error);
  }
};

// Identify a user in PostHog
export const identifyUser = (email: string): void => {
  try {
    posthog.identify(email.toLowerCase());
  } catch (error) {
    console.error("Failed to identify user in PostHog:", error);
  }
};

// Track user login event
export const trackUserLogin = ({ email }: UserLoginPayload): void => {
  try {
    const normalizedEmail = email.toLowerCase();
    identifyUser(normalizedEmail);
    posthog.capture("userLogin", {
      email: normalizedEmail,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error("Failed to track user login:", error);
  }
};

// Track user registration event
export const trackUserRegistration = ({
  email,
  firstName = "",
  lastName = "",
  company = "",
  fullName = "",
}: UserRegistrationPayload): void => {
  try {
    // Parse name if fullName is provided
    let first = firstName;
    let last = lastName;

    if (fullName && (!firstName || !lastName)) {
      const nameParts = fullName.trim().split(" ");
      first = nameParts[0] || "";
      last = nameParts.slice(1).join(" ") || "";
    }

    posthog.capture("userRegistered", {
      email: email.toLowerCase(),
      firstName: first,
      lastName: last,
      company: company,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error("Failed to track user registration:", error);
  }
};

// Track cloud connection success
export const trackCloudConnectionSuccess = ({
  providerType,
  providerAlias,
  scanType,
}: CloudConnectionPayload): void => {
  try {
    posthog.capture("cloudConnectionSuccess", {
      providerType: providerType,
      providerAlias: providerAlias,
      scanType: scanType,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error("Failed to track cloud connection success:", error);
  }
};

// Generic event tracking function for custom events
export const trackEvent = (
  eventName: string,
  properties?: Record<string, any>,
): void => {
  try {
    posthog.capture(eventName, {
      ...properties,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error(`Failed to track event "${eventName}":`, error);
  }
};

// Track page view
export const trackPageView = (
  pageName: string,
  properties?: Record<string, any>,
): void => {
  try {
    posthog.capture("$pageview", {
      $current_url: window.location.href,
      pageName,
      ...properties,
    });
  } catch (error) {
    console.error("Failed to track page view:", error);
  }
};

// Set user properties
export const setUserProperties = (properties: Record<string, any>): void => {
  try {
    posthog.people.set(properties);
  } catch (error) {
    console.error("Failed to set user properties:", error);
  }
};

// Check if PostHog is initialized and ready
export const isAnalyticsReady = (): boolean => {
  try {
    return (
      typeof posthog !== "undefined" && posthog._isIdentified !== undefined
    );
  } catch {
    return false;
  }
};
