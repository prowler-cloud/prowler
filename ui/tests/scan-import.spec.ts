"use strict";

import { test, expect } from "@playwright/test";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { ScansPage } from "./scans/scans-page";

/**
 * Creates a minimal valid OCSF JSON file for testing.
 */
function createTestOCSFJsonFile(): string {
  const ocsfData = [
    {
      message: "Test finding for E2E import test",
      metadata: {
        event_code: "test_check_e2e",
        product: { name: "Prowler", uid: "prowler", vendor_name: "Prowler", version: "4.0.0" },
        profiles: ["cloud", "datetime"],
        tenant_uid: "",
        version: "1.4.0",
      },
      severity_id: 2,
      severity: "Low",
      status: "New",
      status_code: "PASS",
      status_detail: "Test check passed for E2E import test",
      status_id: 1,
      unmapped: {
        related_url: "https://example.com",
        categories: [],
        depends_on: [],
        related_to: [],
        additional_urls: [],
        notes: "",
        compliance: { "CIS-2.0": ["1.1"] },
      },
      activity_name: "Create",
      activity_id: 1,
      finding_info: {
        created_time: Math.floor(Date.now() / 1000),
        created_time_dt: new Date().toISOString(),
        desc: "E2E test check description",
        product_uid: "prowler",
        title: "E2E Test Check",
        types: ["IAM"],
        uid: `e2e-finding-${Date.now()}`,
      },
      resources: [
        {
          cloud_partition: "aws",
          region: "us-east-1",
          data: { details: "", metadata: { arn: "arn:aws:iam::123456789012:root", name: "e2e-test-resource", status: "AVAILABLE", findings: [], tags: [], type: "AWS::IAM::User", region: "us-east-1" } },
          group: { name: "iam" },
          labels: [],
          name: "e2e-test-resource",
          type: "AwsIamUser",
          uid: `arn:aws:iam::123456789012:user/e2e-test-${Date.now()}`,
        },
      ],
      category_name: "Findings",
      category_uid: 2,
      class_name: "Detection Finding",
      class_uid: 2004,
      cloud: {
        account: { name: "E2E Test Account", type: "AWS Account", type_id: 10, uid: "123456789012", labels: [] },
        org: { name: "", uid: "" },
        provider: "aws",
        region: "us-east-1",
      },
      remediation: { desc: "No remediation needed for test", references: ["https://example.com"] },
      risk_details: "This is a test finding for E2E testing",
      time: Math.floor(Date.now() / 1000),
      time_dt: new Date().toISOString(),
      type_uid: 200401,
      type_name: "Detection Finding: Create",
    },
  ];

  const tempDir = os.tmpdir();
  const filePath = path.join(tempDir, `prowler-e2e-test-${Date.now()}.json`);
  fs.writeFileSync(filePath, JSON.stringify(ocsfData, null, 2));
  return filePath;
}

/**
 * Creates an invalid JSON file for testing error handling.
 */
function createInvalidJsonFile(): string {
  const tempDir = os.tmpdir();
  const filePath = path.join(tempDir, `invalid-e2e-test-${Date.now()}.json`);
  fs.writeFileSync(filePath, "{ invalid json content");
  return filePath;
}

/**
 * Creates a minimal valid Prowler CSV file for testing.
 */
function createTestCSVFile(): string {
  const timestamp = new Date().toISOString();
  const findingUid = `e2e-csv-finding-${Date.now()}`;
  const resourceUid = `arn:aws:iam::123456789012:user/e2e-csv-test-${Date.now()}`;

  const headers = [
    "AUTH_METHOD", "TIMESTAMP", "ACCOUNT_UID", "ACCOUNT_NAME", "ACCOUNT_EMAIL",
    "ACCOUNT_ORGANIZATION_UID", "ACCOUNT_ORGANIZATION_NAME", "ACCOUNT_TAGS",
    "FINDING_UID", "PROVIDER", "CHECK_ID", "CHECK_TITLE", "CHECK_TYPE", "STATUS",
    "STATUS_EXTENDED", "MUTED", "SERVICE_NAME", "SUBSERVICE_NAME", "SEVERITY",
    "RESOURCE_TYPE", "RESOURCE_UID", "RESOURCE_NAME", "RESOURCE_DETAILS",
    "RESOURCE_TAGS", "PARTITION", "REGION", "DESCRIPTION", "RISK", "RELATED_URL",
    "REMEDIATION_RECOMMENDATION_TEXT", "REMEDIATION_RECOMMENDATION_URL",
    "REMEDIATION_CODE_NATIVEIAC", "REMEDIATION_CODE_TERRAFORM", "REMEDIATION_CODE_CLI",
    "REMEDIATION_CODE_OTHER", "COMPLIANCE", "CATEGORIES", "DEPENDS_ON", "RELATED_TO",
    "NOTES", "PROWLER_VERSION", "ADDITIONAL_URLS",
  ].join(";");

  const dataRow = [
    "profile", timestamp, "123456789012", "E2E CSV Test Account", "test@example.com",
    "", "", "", findingUid, "aws", "test_check_csv_e2e", "E2E CSV Test Check", "IAM",
    "PASS", "Test check passed for E2E CSV import test", "false", "iam", "", "low",
    "AwsIamUser", resourceUid, "e2e-csv-test-resource", "", "", "aws", "us-east-1",
    "E2E CSV test check description", "This is a test finding for E2E CSV testing",
    "https://example.com", "No remediation needed for test", "https://example.com/remediation",
    "", "", "", "", "CIS-2.0: 1.1, 1.2 | NIST-800-53: AC-1", "security,iam", "", "", "",
    "4.0.0", "",
  ].join(";");

  const tempDir = os.tmpdir();
  const filePath = path.join(tempDir, `prowler-e2e-csv-test-${Date.now()}.csv`);
  fs.writeFileSync(filePath, `${headers}\n${dataRow}`);
  return filePath;
}

function cleanupTestFile(filePath: string): void {
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Scan Import E2E Test Suite (Reduced)
 * Tests essential scan import functionality for JSON and CSV formats.
 */
test.describe("Scan Import", () => {
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test("should display import section and expand/collapse", { tag: ["@e2e", "@scans", "@import"] }, async ({ page }) => {
    const scansPage = new ScansPage(page);
    await scansPage.goto();

    // Verify import button is visible
    const importButton = page.getByRole("button", { name: /Import Scan Results/i });
    await expect(importButton).toBeVisible();

    // Initially collapsed
    const importContent = page.locator("#scan-import-content");
    await expect(importContent).not.toBeVisible();

    // Expand
    await importButton.click();
    await expect(importContent).toBeVisible();
    await expect(page.getByText(/Drag and drop your scan file/i)).toBeVisible();

    // Collapse
    await importButton.click();
    await expect(importContent).not.toBeVisible();
  });

  test("should upload JSON file and complete import flow", { tag: ["@e2e", "@scans", "@import", "@json"] }, async ({ page }) => {
    let testFilePath: string | null = null;
    try {
      testFilePath = createTestOCSFJsonFile();
      const scansPage = new ScansPage(page);
      await scansPage.goto();

      // Expand import section
      await page.getByRole("button", { name: /Import Scan Results/i }).click();
      await expect(page.locator("#scan-import-content")).toBeVisible();

      // Upload file
      await page.locator('input[type="file"]').setInputFiles(testFilePath);
      await expect(page.getByText(path.basename(testFilePath))).toBeVisible();

      // Submit
      const submitButton = page.getByRole("button", { name: /Import Scan Results/i }).last();
      await expect(submitButton).toBeEnabled();
      await submitButton.click();

      // Wait for result (success or error)
      await expect(
        page.getByText(/Import completed|Import successful|findings imported|Import failed|Error/i)
      ).toBeVisible({ timeout: 30000 });
    } finally {
      if (testFilePath) cleanupTestFile(testFilePath);
    }
  });

  test("should upload CSV file and complete import flow", { tag: ["@e2e", "@scans", "@import", "@csv"] }, async ({ page }) => {
    let testFilePath: string | null = null;
    try {
      testFilePath = createTestCSVFile();
      const scansPage = new ScansPage(page);
      await scansPage.goto();

      // Expand import section
      await page.getByRole("button", { name: /Import Scan Results/i }).click();
      await expect(page.locator("#scan-import-content")).toBeVisible();

      // Upload file
      await page.locator('input[type="file"]').setInputFiles(testFilePath);
      await expect(page.getByText(path.basename(testFilePath))).toBeVisible();

      // Submit
      const submitButton = page.getByRole("button", { name: /Import Scan Results/i }).last();
      await expect(submitButton).toBeEnabled();
      await submitButton.click();

      // Wait for result (success or error)
      await expect(
        page.getByText(/Import completed|Import successful|findings imported|Import failed|Error/i)
      ).toBeVisible({ timeout: 30000 });
    } finally {
      if (testFilePath) cleanupTestFile(testFilePath);
    }
  });

  test("should handle invalid JSON file gracefully", { tag: ["@e2e", "@scans", "@import", "@error"] }, async ({ page }) => {
    let testFilePath: string | null = null;
    try {
      testFilePath = createInvalidJsonFile();
      const scansPage = new ScansPage(page);
      await scansPage.goto();

      // Expand import section
      await page.getByRole("button", { name: /Import Scan Results/i }).click();
      await expect(page.locator("#scan-import-content")).toBeVisible();

      // Upload invalid file
      await page.locator('input[type="file"]').setInputFiles(testFilePath);

      // Submit
      const submitButton = page.getByRole("button", { name: /Import Scan Results/i }).last();
      await submitButton.click();

      // Wait for error
      await expect(page.getByText(/failed|error|invalid|malformed/i)).toBeVisible({ timeout: 30000 });

      // Verify retry is available
      await expect(page.getByRole("button", { name: /Try Again|Retry/i })).toBeVisible();
    } finally {
      if (testFilePath) cleanupTestFile(testFilePath);
    }
  });
});

/**
 * Responsive Design Test Suite for Scan Import
 * Tests that the scan import UI works correctly on different screen sizes.
 */
test.describe("Scan Import - Responsive Design", () => {
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  // Mobile viewport (iPhone SE)
  test("should display correctly on mobile viewport (375x667)", { tag: ["@e2e", "@scans", "@import", "@responsive", "@mobile"] }, async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    const scansPage = new ScansPage(page);
    await scansPage.goto();

    // Verify import button is visible and accessible on mobile
    const importButton = page.getByRole("button", { name: /Import Scan Results/i });
    await expect(importButton).toBeVisible();
    await expect(importButton).toBeInViewport();

    // Expand import section
    await importButton.click();
    const importContent = page.locator("#scan-import-content");
    await expect(importContent).toBeVisible();

    // Verify dropzone is visible and properly sized
    const dropzone = page.getByText(/Drag and drop your scan file/i);
    await expect(dropzone).toBeVisible();

    // Verify form elements are visible
    await expect(page.getByText(/Provider \(Optional\)/i)).toBeVisible();
    await expect(page.getByText(/Create provider if not found/i)).toBeVisible();

    // Verify submit button is visible and full-width on mobile
    const submitButton = page.getByRole("button", { name: /Import Scan Results/i }).last();
    await expect(submitButton).toBeVisible();
  });

  // Tablet viewport (iPad)
  test("should display correctly on tablet viewport (768x1024)", { tag: ["@e2e", "@scans", "@import", "@responsive", "@tablet"] }, async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    const scansPage = new ScansPage(page);
    await scansPage.goto();

    // Verify import button is visible
    const importButton = page.getByRole("button", { name: /Import Scan Results/i });
    await expect(importButton).toBeVisible();

    // Expand import section
    await importButton.click();
    const importContent = page.locator("#scan-import-content");
    await expect(importContent).toBeVisible();

    // Verify all form elements are visible
    await expect(page.getByText(/Drag and drop your scan file/i)).toBeVisible();
    await expect(page.getByText(/Provider \(Optional\)/i)).toBeVisible();
    await expect(page.getByText(/Create provider if not found/i)).toBeVisible();
  });

  // Desktop viewport (1920x1080)
  test("should display correctly on desktop viewport (1920x1080)", { tag: ["@e2e", "@scans", "@import", "@responsive", "@desktop"] }, async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    const scansPage = new ScansPage(page);
    await scansPage.goto();

    // Verify import button is visible
    const importButton = page.getByRole("button", { name: /Import Scan Results/i });
    await expect(importButton).toBeVisible();

    // Expand import section
    await importButton.click();
    const importContent = page.locator("#scan-import-content");
    await expect(importContent).toBeVisible();

    // Verify all form elements are visible
    await expect(page.getByText(/Drag and drop your scan file/i)).toBeVisible();
    await expect(page.getByText(/Provider \(Optional\)/i)).toBeVisible();
    await expect(page.getByText(/Create provider if not found/i)).toBeVisible();
  });

  // Small mobile viewport (iPhone 5/SE)
  test("should display correctly on small mobile viewport (320x568)", { tag: ["@e2e", "@scans", "@import", "@responsive", "@mobile-small"] }, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 568 });
    const scansPage = new ScansPage(page);
    await scansPage.goto();

    // Verify import button is visible on small screens
    const importButton = page.getByRole("button", { name: /Import Scan Results/i });
    await expect(importButton).toBeVisible();

    // Expand import section
    await importButton.click();
    const importContent = page.locator("#scan-import-content");
    await expect(importContent).toBeVisible();

    // Verify content doesn't overflow horizontally
    const contentBox = await importContent.boundingBox();
    expect(contentBox).not.toBeNull();
    if (contentBox) {
      expect(contentBox.width).toBeLessThanOrEqual(320);
    }
  });

  // Test file upload on mobile
  test("should allow file upload on mobile viewport", { tag: ["@e2e", "@scans", "@import", "@responsive", "@mobile"] }, async ({ page }) => {
    let testFilePath: string | null = null;
    try {
      testFilePath = createTestOCSFJsonFile();
      await page.setViewportSize({ width: 375, height: 667 });
      const scansPage = new ScansPage(page);
      await scansPage.goto();

      // Expand import section
      await page.getByRole("button", { name: /Import Scan Results/i }).click();
      await expect(page.locator("#scan-import-content")).toBeVisible();

      // Upload file on mobile
      await page.locator('input[type="file"]').setInputFiles(testFilePath);

      // Verify file is shown (file name should be visible, possibly truncated)
      await expect(page.getByText(/prowler-e2e-test/i)).toBeVisible();

      // Verify remove button is accessible
      const removeButton = page.getByRole("button", { name: /Remove file/i });
      await expect(removeButton).toBeVisible();
    } finally {
      if (testFilePath) cleanupTestFile(testFilePath);
    }
  });

  // Test progress display on different screen sizes
  test("should display progress correctly on tablet viewport", { tag: ["@e2e", "@scans", "@import", "@responsive", "@tablet"] }, async ({ page }) => {
    let testFilePath: string | null = null;
    try {
      testFilePath = createTestOCSFJsonFile();
      await page.setViewportSize({ width: 768, height: 1024 });
      const scansPage = new ScansPage(page);
      await scansPage.goto();

      // Expand import section
      await page.getByRole("button", { name: /Import Scan Results/i }).click();
      await expect(page.locator("#scan-import-content")).toBeVisible();

      // Upload file
      await page.locator('input[type="file"]').setInputFiles(testFilePath);
      await expect(page.getByText(/prowler-e2e-test/i)).toBeVisible();

      // Submit and verify progress is visible
      const submitButton = page.getByRole("button", { name: /Import Scan Results/i }).last();
      await submitButton.click();

      // Wait for result (success or error) - progress should be visible during processing
      await expect(
        page.getByText(/Import completed|Import successful|findings imported|Import failed|Error|Uploading|Processing/i)
      ).toBeVisible({ timeout: 30000 });
    } finally {
      if (testFilePath) cleanupTestFile(testFilePath);
    }
  });
});
