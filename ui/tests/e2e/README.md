# Playwright E2E Testing

## 📦 Installation

Playwright is already set up. To install dependencies:

```bash
cd ui
npm install

# Run all tests (headless)
npm run test:e2e

# Run specific file (headless)
npx playwright test tests/e2e/root.spec.ts

# Run all tests with UI (headed mode)
npx playwright test --headed

# Run specific file with UI (headed mode)
npx playwright test tests/e2e/root.spec.ts --headed

# Open the HTML report from last test run
npx playwright show-report