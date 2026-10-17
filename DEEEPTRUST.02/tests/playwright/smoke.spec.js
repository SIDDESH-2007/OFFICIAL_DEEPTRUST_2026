const { test, expect } = require('@playwright/test');

test.describe('DeepTrust Smoke Test', () => {
  test('Application should load without critical errors', async ({ page }) => {
    const errors = [];
    page.on('pageerror', exception => {
      errors.push(`Page error: ${exception}`);
    });
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(`Console error: ${msg.text()}`);
      }
    });

    const networkErrors = [];
    page.on('response', response => {
      if (response.status() >= 400 && response.status() !== 401 && response.status() !== 403) {
        networkErrors.push(`Network error: ${response.status()} ${response.url()}`);
      }
    });

    await page.goto('/');

    // Check for blank page
    const content = await page.content();
    expect(content.length).toBeGreaterThan(100);

    // Wait for splash screen to complete (if any) and login form to become visible
    await expect(page.locator('#form-login')).toBeVisible({ timeout: 15000 });

    console.log('Console Errors:', errors);
    console.log('Network Errors:', networkErrors);
  });
});
