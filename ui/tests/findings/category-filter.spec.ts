import { expect, test } from "@playwright/test";

test.describe("Category Filter in Findings", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/findings");
  });

  test("should display category filter", async ({ page }) => {
    const categoryFilter = page.getByText("Category");
    await expect(categoryFilter).toBeVisible();
  });

  test("should filter findings by internet-exposed category", async ({
    page,
  }) => {
    await page.getByText("Category").click();
    await page.getByText("internet-exposed").click();
    await expect(page).toHaveURL(/categories__in=internet-exposed/);
  });

  test("should filter findings by multiple categories", async ({ page }) => {
    await page.getByText("Category").click();
    await page.getByText("internet-exposed").click();
    await page.getByText("encryption").click();
    await expect(page).toHaveURL(/categories__in/);
  });

  test("should clear category filter", async ({ page }) => {
    await page.getByText("Category").click();
    await page.getByText("internet-exposed").click();
    await page.getByText("Clear Filters").click();
    await expect(page).not.toHaveURL(/categories__in/);
  });
});
