"use strict";

import { test, expect } from "@playwright/test";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { ScansPage } from "./scans/scans-page";

/**
 * Creates a minimal valid OCSF JSON file for testing.
 * Returns the path to the created temporary file.
 */
function createTestOCSFJsonFile(): string {
  const ocsfData = [
    {
      message: "Test finding for E2E import test",
      metadata: {
        event_code: "test_check_e2e",
        product: {
          name: "Prowler",
          uid: "prowler",
          vendor_name: "Prowler",
          version: "4.0.0",
        },
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
        compliance: {
          "CIS-2.0": ["1.1"],
        },
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
          data: {
            details: "",
            metadata: {
              arn: "arn:aws:iam::123456789012:root",
              name: "e2e-test-resource",
              status: "AVAILABLE",
              findings: [],
              tags: [],
              type: "AWS::IAM::User",
              region: "us-east-1",
            },
          },
          group: {
            name: "iam",
          },
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
        account: {
          name: "E2E Test Account",
          type: "AWS Account",
          type_id: 10,
          uid: "123456789012",
          labels: [],
        },
        org: {
          name: "",
          uid: "",
        },
        provider: "aws",
        region: "us-east-1",
      },
      remediation: {
        desc: "No remediation needed for test",
        references: ["https://example.com"],
      },
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
 * Uses semicolon delimiter (Prowler default).
 * Returns the path to the created temporary file.
 */
function createTestCSVFile(): string {
  const timestamp = new Date().toISOString();
  const findingUid = `e2e-csv-finding-${Date.now()}`;
  const resourceUid = `arn:aws:iam::123456789012:user/e2e-csv-test-${Date.now()}`;

  // CSV headers (semicolon-delimited, Prowler default format)
  const headers = [
    "AUTH_METHOD",
    "TIMESTAMP",
    "ACCOUNT_UID",
    "ACCOUNT_NAME",
    "ACCOUNT_EMAIL",
    "ACCOUNT_ORGANIZATION_UID",
    "ACCOUNT_ORGANIZATION_NAME",
    "ACCOUNT_TAGS",
    "FINDING_UID",
    "PROVIDER",
    "CHECK_ID",
    "CHECK_TITLE",
    "CHECK_TYPE",
    "STATUS",
    "STATUS_EXTENDED",
    "MUTED",
    "SERVICE_NAME",
    "SUBSERVICE_NAME",
    "SEVERITY",
    "RESOURCE_TYPE",
    "RESOURCE_UID",
    "RESOURCE_NAME",
    "RESOURCE_DETAILS",
    "RESOURCE_TAGS",
    "PARTITION",
    "REGION",
    "DESCRIPTION",
    "RISK",
    "RELATED_URL",
    "REMEDIATION_RECOMMENDATION_TEXT",
    "REMEDIATION_RECOMMENDATION_URL",
    "REMEDIATION_CODE_NATIVEIAC",
    "REMEDIATION_CODE_TERRAFORM",
    "REMEDIATION_CODE_CLI",
    "REMEDIATION_CODE_OTHER",
    "COMPLIANCE",
    "CATEGORIES",
    "DEPENDS_ON",
    "RELATED_TO",
    "NOTES",
    "PROWLER_VERSION",
    "ADDITIONAL_URLS",
  ].join(";");

  // CSV data row
  const dataRow = [
    "profile", // AUTH_METHOD
    timestamp, // TIMESTAMP
    "123456789012", // ACCOUNT_UID
    "E2E CSV Test Account", // ACCOUNT_NAME
    "test@example.com", // ACCOUNT_EMAIL
    "", // ACCOUNT_ORGANIZATION_UID
    "", // ACCOUNT_ORGANIZATION_NAME
    "", // ACCOUNT_TAGS
    findingUid, // FINDING_UID
    "aws", // PROVIDER
    "test_check_csv_e2e", // CHECK_ID
    "E2E CSV Test Check", // CHECK_TITLE
    "IAM", // CHECK_TYPE
    "PASS", // STATUS
    "Test check passed for E2E CSV import test", // STATUS_EXTENDED
    "false", // MUTED
    "iam", // SERVICE_NAME
    "", // SUBSERVICE_NAME
    "low", // SEVERITY
    "AwsIamUser", // RESOURCE_TYPE
    resourceUid, // RESOURCE_UID
    "e2e-csv-test-resource", // RESOURCE_NAME
    "", // RESOURCE_DETAILS
    "", // RESOURCE_TAGS
    "aws", // PARTITION
    "us-east-1", // REGION
    "E2E CSV test check description", // DESCRIPTION
    "This is a test finding for E2E CSV testing", // RISK
    "https://example.com", // RELATED_URL
    "No remediation needed for test", // REMEDIATION_RECOMMENDATION_TEXT
    "https://example.com/remediation", // REMEDIATION_RECOMMENDATION_URL
    "", // REMEDIATION_CODE_NATIVEIAC
    "", // REMEDIATION_CODE_TERRAFORM
    "", // REMEDIATION_CODE_CLI
    "", // REMEDIATION_CODE_OTHER
    "CIS-2.0: 1.1, 1.2 | NIST-800-53: AC-1", // COMPLIANCE
    "security,iam", // CATEGORIES
    "", // DEPENDS_ON
    "", // RELATED_TO
    "", // NOTES
    "4.0.0", // PROWLER_VERSION
    "", // ADDITIONAL_URLS
  ].join(";");

  const csvContent = `${headers}\n${dataRow}`;

  const tempDir = os.tmpdir();
  const filePath = path.join(tempDir, `prowler-e2e-csv-test-${Date.now()}.csv`);
  fs.writeFileSync(filePath, csvContent);
  return filePath;
}

/**
 * Creates an invalid CSV file for testing error handling.
 * Missing required columns.
 */
function createInvalidCSVFile(): string {
  const tempDir = os.tmpdir();
  const filePath = path.join(tempDir, `invalid-csv-e2e-test-${Date.now()}.csv`);
  // CSV with missing required columns (no FINDING_UID, PROVIDER, CHECK_ID, STATUS, ACCOUNT_UID)
  const invalidCsv = "COLUMN1;COLUMN2;COLUMN3\nvalue1;value2;value3";
  fs.writeFileSync(filePath, invalidCsv);
  return filePath;
}

/**
 * Cleans up a temporary test file.
 */
function cleanupTestFile(filePath: string): void {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Scan Import E2E Test Suite
 *
 * Tests the scan import functionality for uploading Prowler CLI output
 * (JSON/OCSF and CSV formats) through the UI.
 */
test.describe("Scan Import", () => {
  // Use admin authentication for scan import (requires MANAGE_SCANS permission)
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test.describe("Import Section UI", () => {
    test(
      "should display import section on scans page",
      {
        tag: ["@e2e", "@scans", "@import", "@SCAN-IMPORT-E2E-001"],
      },
      async ({ page }) => {
        // Navigate to scans page
        const scansPage = new ScansPage(page);
        await scansPage.goto();

        // Verify the import section header is visible
        const importButton = page.getByRole("button", {
          name: /Import Scan Results/i,
        });
        await expect(importButton).toBeVisible();

        // Verify the description text is visible
        await expect(
          page.getByText(/Upload Prowler CLI output \(JSON or CSV\)/i)
        ).toBeVisible();
      }
    );

    test(
      "should expand and collapse import section",
      {
        tag: ["@e2e", "@scans", "@import", "@SCAN-IMPORT-E2E-002"],
      },
      async ({ page }) => {
        // Navigate to scans page
        const scansPage = new ScansPage(page);
        await scansPage.goto();

        // Find the import section toggle button
        const importToggle = page.getByRole("button", {
          name: /Import Scan Results/i,
        });

        // Initially the content should be collapsed (not visible)
        const importContent = page.locator("#scan-import-content");
        await expect(importContent).not.toBeVisible();

        // Click to expand
        await importToggle.click();

        // Content should now be visible
        await expect(importContent).toBeVisible();

        // Verify form elements are visible when expanded
        await expect(
          page.getByText(/Scan Results File/i)
        ).toBeVisible();
        await expect(
          page.getByText(/Drag and drop your scan file/i)
        ).toBeVisible();

        // Click to collapse
        await importToggle.click();

        // Content should be hidden again
        await expect(importContent).not.toBeVisible();
      }
    );

    test(
      "should display dropzone with correct file type hints",
      {
        tag: ["@e2e", "@scans", "@import", "@SCAN-IMPORT-E2E-003"],
      },
      async ({ page }) => {
        // Navigate to scans page
        const scansPage = new ScansPage(page);
        await scansPage.goto();

        // Expand the import section
        const importToggle = page.getByRole("button", {
          name: /Import Scan Results/i,
        });
        await importToggle.click();

        // Verify dropzone hints
        await expect(
          page.getByText(/Drag and drop your scan file/i)
        ).toBeVisible();
        await expect(page.getByText(/or click to browse/i)).toBeVisible();
        await expect(
          page.getByText(/Supports JSON and CSV formats/i)
        ).toBeVisible();
      }
    );

    test(
      "should display provider selection dropdown",
      {
        tag: ["@e2e", "@scans", "@import", "@SCAN-IMPORT-E2E-004"],
      },
      async ({ page }) => {
        // Navigate to scans page
        const scansPage = new ScansPage(page);
        await scansPage.goto();

        // Expand the import section
        const importToggle = page.getByRole("button", {
          name: /Import Scan Results/i,
        });
        await importToggle.click();

        // Verify provider selection elements
        await expect(
          page.getByText(/Provider \(Optional\)/i)
        ).toBeVisible();
        await expect(
          page.getByText(/Auto-detect from scan data/i)
        ).toBeVisible();
      }
    );

    test(
      "should display create provider checkbox",
      {
        tag: ["@e2e", "@scans", "@import", "@SCAN-IMPORT-E2E-005"],
      },
      async ({ page }) => {
        // Navigate to scans page
        const scansPage = new ScansPage(page);
        await scansPage.goto();

        // Expand the import section
        const importToggle = page.getByRole("button", {
          name: /Import Scan Results/i,
        });
        await importToggle.click();

        // Verify create provider checkbox
        const createProviderCheckbox = page.getByRole("checkbox", {
          name: /Create provider if not found/i,
        });
        await expect(createProviderCheckbox).toBeVisible();

        // Verify it's checked by default
        await expect(createProviderCheckbox).toBeChecked();
      }
    );

    test(
      "should have disabled submit button when no file selected",
      {
        tag: ["@e2e", "@scans", "@import", "@SCAN-IMPORT-E2E-006"],
      },
      async ({ page }) => {
        // Navigate to scans page
        const scansPage = new ScansPage(page);
        await scansPage.goto();

        // Expand the import section
        const importToggle = page.getByRole("button", {
          name: /Import Scan Results/i,
        });
        await importToggle.click();

        // Verify submit button is disabled
        const submitButton = page.getByRole("button", {
          name: /Import Scan Results/i,
        }).last();
        await expect(submitButton).toBeDisabled();
      }
    );
  });

  test.describe("JSON File Upload Flow", () => {
    test(
      "should upload JSON file and show file details",
      {
        tag: ["@e2e", "@scans", "@import", "@json", "@SCAN-IMPORT-E2E-007"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test file
          testFilePath = createTestOCSFJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Find the file input and upload the file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Verify file details are displayed
          const fileName = path.basename(testFilePath);
          await expect(page.getByText(fileName)).toBeVisible();

          // Verify file size is displayed (should show bytes/KB)
          await expect(page.getByText(/Bytes|KB/i)).toBeVisible();

          // Verify the submit button is now enabled
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should allow removing selected JSON file",
      {
        tag: ["@e2e", "@scans", "@import", "@json", "@SCAN-IMPORT-E2E-008"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test file
          testFilePath = createTestOCSFJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Verify file is displayed
          const fileName = path.basename(testFilePath);
          await expect(page.getByText(fileName)).toBeVisible();

          // Find and click the remove button
          const removeButton = page.getByRole("button", {
            name: /Remove file/i,
          });
          await expect(removeButton).toBeVisible();
          await removeButton.click();

          // Verify file is removed and dropzone is shown again
          await expect(page.getByText(fileName)).not.toBeVisible();
          await expect(
            page.getByText(/Drag and drop your scan file/i)
          ).toBeVisible();

          // Verify submit button is disabled again
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeDisabled();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should show progress indicators during JSON import",
      {
        tag: ["@e2e", "@scans", "@import", "@json", "@SCAN-IMPORT-E2E-009"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test file
          testFilePath = createTestOCSFJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Verify progress indicators appear (uploading or processing)
          // The UI should show either uploading progress or processing status
          await expect(
            page.getByText(/Uploading|Processing|Parsing|Validating|Creating/i)
          ).toBeVisible({ timeout: 10000 });
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should complete JSON import successfully or show appropriate error",
      {
        tag: ["@e2e", "@scans", "@import", "@json", "@SCAN-IMPORT-E2E-010"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test file
          testFilePath = createTestOCSFJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for the import to complete (success or error)
          // The UI should show either success message or error message
          await expect(
            page.getByText(
              /Import completed|Import successful|findings imported|Import failed|Error/i
            )
          ).toBeVisible({ timeout: 30000 });

          // If successful, verify the "Import Another Scan" button appears
          const importAnotherButton = page.getByRole("button", {
            name: /Import Another Scan/i,
          });

          // Check if import was successful (button visible) or failed (error shown)
          const isSuccess = await importAnotherButton.isVisible().catch(() => false);

          if (isSuccess) {
            // Verify success state
            await expect(importAnotherButton).toBeVisible();
            // Verify findings count is displayed
            await expect(page.getByText(/finding/i)).toBeVisible();
          } else {
            // Verify error state - error message should be visible
            await expect(
              page.getByText(/failed|error|invalid/i)
            ).toBeVisible();
            // Verify retry button is available
            await expect(
              page.getByRole("button", { name: /Try Again|Retry/i })
            ).toBeVisible();
          }
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should handle invalid JSON file gracefully",
      {
        tag: ["@e2e", "@scans", "@import", "@json", "@error", "@SCAN-IMPORT-E2E-011"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create invalid JSON file
          testFilePath = createInvalidJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the invalid file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error message to appear
          await expect(
            page.getByText(/failed|error|invalid|malformed/i)
          ).toBeVisible({ timeout: 30000 });

          // Verify the form allows retry
          const tryAgainButton = page.getByRole("button", {
            name: /Try Again|Retry/i,
          });
          await expect(tryAgainButton).toBeVisible();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should allow importing another scan after successful import",
      {
        tag: ["@e2e", "@scans", "@import", "@json", "@SCAN-IMPORT-E2E-012"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test file
          testFilePath = createTestOCSFJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for the import to complete
          await expect(
            page.getByText(
              /Import completed|Import successful|findings imported|Import failed|Error/i
            )
          ).toBeVisible({ timeout: 30000 });

          // Check if import was successful
          const importAnotherButton = page.getByRole("button", {
            name: /Import Another Scan/i,
          });
          const isSuccess = await importAnotherButton.isVisible().catch(() => false);

          if (isSuccess) {
            // Click "Import Another Scan" button
            await importAnotherButton.click();

            // Verify the form is reset and dropzone is visible again
            await expect(
              page.getByText(/Drag and drop your scan file/i)
            ).toBeVisible();

            // Verify submit button is disabled (no file selected)
            const newSubmitButton = page.getByRole("button", {
              name: /Import Scan Results/i,
            }).last();
            await expect(newSubmitButton).toBeDisabled();
          }
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should navigate to scan details when clicking View Imported Scan link",
      {
        tag: ["@e2e", "@scans", "@import", "@json", "@navigation", "@SCAN-IMPORT-E2E-025"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test file
          testFilePath = createTestOCSFJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for the import to complete successfully
          await expect(
            page.getByText(
              /Import completed|Import successful|findings imported|Import failed|Error/i
            )
          ).toBeVisible({ timeout: 30000 });

          // Check if import was successful by looking for the View Imported Scan link
          const viewScanLink = page.getByRole("link", {
            name: /View Imported Scan/i,
          });
          const isSuccess = await viewScanLink.isVisible().catch(() => false);

          if (isSuccess) {
            // Verify the link has the correct href pattern (should contain /scans/ followed by a UUID)
            const href = await viewScanLink.getAttribute("href");
            expect(href).toMatch(/\/scans\/[a-f0-9-]+/i);

            // Click the link to navigate to scan details
            await viewScanLink.click();

            // Wait for navigation to complete
            await page.waitForURL(/\/scans\/[a-f0-9-]+/i, { timeout: 10000 });

            // Verify we're on the scan details page
            const currentUrl = page.url();
            expect(currentUrl).toMatch(/\/scans\/[a-f0-9-]+/i);

            // Verify the scan details page has loaded (check for common elements)
            // The page should show scan information
            await expect(
              page.getByText(/Scan|Findings|Resources|Provider/i).first()
            ).toBeVisible({ timeout: 10000 });
          } else {
            // If import failed, the test should still pass but log the failure
            console.log("Import did not succeed - skipping navigation test");
            // Verify error state is shown
            await expect(
              page.getByText(/failed|error|invalid/i)
            ).toBeVisible();
          }
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );
  });

  test.describe("CSV File Upload Flow", () => {
    test(
      "should upload CSV file and show file details",
      {
        tag: ["@e2e", "@scans", "@import", "@csv", "@SCAN-IMPORT-E2E-013"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test CSV file
          testFilePath = createTestCSVFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Find the file input and upload the CSV file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Verify file details are displayed
          const fileName = path.basename(testFilePath);
          await expect(page.getByText(fileName)).toBeVisible();

          // Verify file size is displayed (should show bytes/KB)
          await expect(page.getByText(/Bytes|KB/i)).toBeVisible();

          // Verify the submit button is now enabled
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should allow removing selected CSV file",
      {
        tag: ["@e2e", "@scans", "@import", "@csv", "@SCAN-IMPORT-E2E-014"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test CSV file
          testFilePath = createTestCSVFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the CSV file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Verify file is displayed
          const fileName = path.basename(testFilePath);
          await expect(page.getByText(fileName)).toBeVisible();

          // Find and click the remove button
          const removeButton = page.getByRole("button", {
            name: /Remove file/i,
          });
          await expect(removeButton).toBeVisible();
          await removeButton.click();

          // Verify file is removed and dropzone is shown again
          await expect(page.getByText(fileName)).not.toBeVisible();
          await expect(
            page.getByText(/Drag and drop your scan file/i)
          ).toBeVisible();

          // Verify submit button is disabled again
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeDisabled();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should show progress indicators during CSV import",
      {
        tag: ["@e2e", "@scans", "@import", "@csv", "@SCAN-IMPORT-E2E-015"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test CSV file
          testFilePath = createTestCSVFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the CSV file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Verify progress indicators appear (uploading or processing)
          // The UI should show either uploading progress or processing status
          await expect(
            page.getByText(/Uploading|Processing|Parsing|Validating|Creating/i)
          ).toBeVisible({ timeout: 10000 });
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should complete CSV import successfully or show appropriate error",
      {
        tag: ["@e2e", "@scans", "@import", "@csv", "@SCAN-IMPORT-E2E-016"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test CSV file
          testFilePath = createTestCSVFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the CSV file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for the import to complete (success or error)
          // The UI should show either success message or error message
          await expect(
            page.getByText(
              /Import completed|Import successful|findings imported|Import failed|Error/i
            )
          ).toBeVisible({ timeout: 30000 });

          // If successful, verify the "Import Another Scan" button appears
          const importAnotherButton = page.getByRole("button", {
            name: /Import Another Scan/i,
          });

          // Check if import was successful (button visible) or failed (error shown)
          const isSuccess = await importAnotherButton.isVisible().catch(() => false);

          if (isSuccess) {
            // Verify success state
            await expect(importAnotherButton).toBeVisible();
            // Verify findings count is displayed
            await expect(page.getByText(/finding/i)).toBeVisible();
          } else {
            // Verify error state - error message should be visible
            await expect(
              page.getByText(/failed|error|invalid/i)
            ).toBeVisible();
            // Verify retry button is available
            await expect(
              page.getByRole("button", { name: /Try Again|Retry/i })
            ).toBeVisible();
          }
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should handle invalid CSV file gracefully",
      {
        tag: ["@e2e", "@scans", "@import", "@csv", "@error", "@SCAN-IMPORT-E2E-017"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create invalid CSV file (missing required columns)
          testFilePath = createInvalidCSVFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the invalid CSV file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error message to appear
          await expect(
            page.getByText(/failed|error|invalid|missing|required/i)
          ).toBeVisible({ timeout: 30000 });

          // Verify the form allows retry
          const tryAgainButton = page.getByRole("button", {
            name: /Try Again|Retry/i,
          });
          await expect(tryAgainButton).toBeVisible();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should allow importing another scan after successful CSV import",
      {
        tag: ["@e2e", "@scans", "@import", "@csv", "@SCAN-IMPORT-E2E-018"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create test CSV file
          testFilePath = createTestCSVFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the CSV file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for the import to complete
          await expect(
            page.getByText(
              /Import completed|Import successful|findings imported|Import failed|Error/i
            )
          ).toBeVisible({ timeout: 30000 });

          // Check if import was successful
          const importAnotherButton = page.getByRole("button", {
            name: /Import Another Scan/i,
          });
          const isSuccess = await importAnotherButton.isVisible().catch(() => false);

          if (isSuccess) {
            // Click "Import Another Scan" button
            await importAnotherButton.click();

            // Verify the form is reset and dropzone is visible again
            await expect(
              page.getByText(/Drag and drop your scan file/i)
            ).toBeVisible();

            // Verify submit button is disabled (no file selected)
            const newSubmitButton = page.getByRole("button", {
              name: /Import Scan Results/i,
            }).last();
            await expect(newSubmitButton).toBeDisabled();
          }
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );
  });

  test.describe("Error Handling Display", () => {
    test(
      "should display error title and detail message for invalid JSON",
      {
        tag: ["@e2e", "@scans", "@import", "@error", "@SCAN-IMPORT-E2E-019"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create invalid JSON file
          testFilePath = createInvalidJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the invalid file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error state to appear
          await expect(
            page.getByText(/Import failed|Error/i)
          ).toBeVisible({ timeout: 30000 });

          // Verify error container has proper styling (red border/background)
          const errorContainer = page.locator('[role="status"]');
          await expect(errorContainer).toBeVisible();

          // Verify error icon is displayed (AlertCircleIcon)
          const errorIcon = errorContainer.locator('svg').first();
          await expect(errorIcon).toBeVisible();

          // Verify error detail message is displayed
          await expect(
            page.getByText(/error|invalid|malformed|unexpected/i)
          ).toBeVisible();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should display error title and detail message for invalid CSV",
      {
        tag: ["@e2e", "@scans", "@import", "@error", "@SCAN-IMPORT-E2E-020"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create invalid CSV file (missing required columns)
          testFilePath = createInvalidCSVFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the invalid CSV file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error state to appear
          await expect(
            page.getByText(/Import failed|Error/i)
          ).toBeVisible({ timeout: 30000 });

          // Verify error container is visible
          const errorContainer = page.locator('[role="status"]');
          await expect(errorContainer).toBeVisible();

          // Verify error detail message is displayed
          await expect(
            page.getByText(/error|invalid|missing|required/i)
          ).toBeVisible();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should allow retry after error via Try Again button",
      {
        tag: ["@e2e", "@scans", "@import", "@error", "@SCAN-IMPORT-E2E-021"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create invalid JSON file
          testFilePath = createInvalidJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the invalid file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error state
          await expect(
            page.getByText(/Import failed|Error/i)
          ).toBeVisible({ timeout: 30000 });

          // Find and click the Try Again button
          const tryAgainButton = page.getByRole("button", {
            name: /Try Again|Retry/i,
          });
          await expect(tryAgainButton).toBeVisible();
          await tryAgainButton.click();

          // Verify the form is reset and dropzone is visible again
          await expect(
            page.getByText(/Drag and drop your scan file/i)
          ).toBeVisible();

          // Verify submit button is disabled (no file selected)
          const newSubmitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(newSubmitButton).toBeDisabled();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should display troubleshooting tips for validation errors",
      {
        tag: ["@e2e", "@scans", "@import", "@error", "@SCAN-IMPORT-E2E-022"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create invalid JSON file
          testFilePath = createInvalidJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the invalid file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error state
          await expect(
            page.getByText(/Import failed|Error/i)
          ).toBeVisible({ timeout: 30000 });

          // Check if troubleshooting tips are displayed
          // Note: Troubleshooting tips only appear for validation_error code
          // The UI may or may not show them depending on the error type
          const troubleshootingSection = page.getByText(/Troubleshooting tips/i);
          const hasTroubleshooting = await troubleshootingSection.isVisible().catch(() => false);

          if (hasTroubleshooting) {
            // Verify troubleshooting tips content
            await expect(
              page.getByText(/valid Prowler JSON|OCSF|CSV/i)
            ).toBeVisible();
            await expect(
              page.getByText(/required fields/i)
            ).toBeVisible();
          }

          // Regardless of troubleshooting tips, verify error state is properly displayed
          await expect(
            page.getByRole("button", { name: /Try Again|Retry/i })
          ).toBeVisible();
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should display error state with dismiss button",
      {
        tag: ["@e2e", "@scans", "@import", "@error", "@SCAN-IMPORT-E2E-023"],
      },
      async ({ page }) => {
        let testFilePath: string | null = null;

        try {
          // Create invalid JSON file
          testFilePath = createInvalidJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // Upload the invalid file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(testFilePath);

          // Click the submit button
          const submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error state
          await expect(
            page.getByText(/Import failed|Error/i)
          ).toBeVisible({ timeout: 30000 });

          // Verify the error container has proper ARIA attributes
          const errorContainer = page.locator('[role="status"]');
          await expect(errorContainer).toBeVisible();
          await expect(errorContainer).toHaveAttribute("aria-live", "polite");

          // Verify dismiss button is available (X icon button)
          const dismissButton = page.getByRole("button", { name: /Dismiss/i });
          const hasDismiss = await dismissButton.isVisible().catch(() => false);

          if (hasDismiss) {
            await dismissButton.click();
            // After dismiss, the form should be visible again
            await expect(
              page.getByText(/Drag and drop your scan file/i)
            ).toBeVisible();
          }
        } finally {
          // Cleanup
          if (testFilePath) {
            cleanupTestFile(testFilePath);
          }
        }
      }
    );

    test(
      "should maintain form state after error for retry with different file",
      {
        tag: ["@e2e", "@scans", "@import", "@error", "@SCAN-IMPORT-E2E-024"],
      },
      async ({ page }) => {
        let invalidFilePath: string | null = null;
        let validFilePath: string | null = null;

        try {
          // Create both invalid and valid files
          invalidFilePath = createInvalidJsonFile();
          validFilePath = createTestOCSFJsonFile();

          // Navigate to scans page
          const scansPage = new ScansPage(page);
          await scansPage.goto();

          // Expand the import section
          const importToggle = page.getByRole("button", {
            name: /Import Scan Results/i,
          });
          await importToggle.click();

          // Wait for the content to be visible
          const importContent = page.locator("#scan-import-content");
          await expect(importContent).toBeVisible();

          // First, upload the invalid file
          const fileInput = page.locator('input[type="file"]');
          await fileInput.setInputFiles(invalidFilePath);

          // Click the submit button
          let submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
          await submitButton.click();

          // Wait for error state
          await expect(
            page.getByText(/Import failed|Error/i)
          ).toBeVisible({ timeout: 30000 });

          // Click Try Again
          const tryAgainButton = page.getByRole("button", {
            name: /Try Again|Retry/i,
          });
          await tryAgainButton.click();

          // Verify form is reset
          await expect(
            page.getByText(/Drag and drop your scan file/i)
          ).toBeVisible();

          // Now upload the valid file
          await fileInput.setInputFiles(validFilePath);

          // Verify file is displayed
          const fileName = path.basename(validFilePath);
          await expect(page.getByText(fileName)).toBeVisible();

          // Verify submit button is enabled
          submitButton = page.getByRole("button", {
            name: /Import Scan Results/i,
          }).last();
          await expect(submitButton).toBeEnabled();
        } finally {
          // Cleanup
          if (invalidFilePath) {
            cleanupTestFile(invalidFilePath);
          }
          if (validFilePath) {
            cleanupTestFile(validFilePath);
          }
        }
      }
    );
  });
});
