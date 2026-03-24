import { test as testBase } from "vitest";

import { worker } from "./msw/browser";

export const test = testBase.extend<{ worker: typeof worker }>({
  worker: [
    async ({}, use) => {
      await worker.start({ onUnhandledRequest: "error" });
      await use(worker);
      worker.resetHandlers();
      worker.stop();
    },
    { auto: true },
  ],
});

export { expect } from "vitest";
