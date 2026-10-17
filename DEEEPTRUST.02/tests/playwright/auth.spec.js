const { test, expect } = require('@playwright/test');

test.describe('DeepTrust Login UI Test', () => {
  test('Login page UI elements should be present', async ({ page }) => {
    await page.goto('/');

    // Wait for the login form to appear after the boot sequence
    const loginForm = page.locator('#form-login');
    await expect(loginForm).toBeVisible({ timeout: 15000 });

    // Check branding
    await expect(page.locator('h1').filter({ hasText: 'DeepTrust' }).first()).toBeVisible();

    // Check input fields
    const emailInput = page.locator('#input-email');
    await expect(emailInput).toBeVisible();

    const passwordInput = page.locator('#input-password');
    await expect(passwordInput).toBeVisible();

    // Check buttons
    const loginButton = page.locator('#form-login button[type="button"], #form-login button[type="submit"]').first();
    await expect(loginButton).toBeVisible();

    // Test input
    await emailInput.fill('test@example.com');
    await expect(emailInput).toHaveValue('test@example.com');

    await passwordInput.fill('password123');
    await expect(passwordInput).toHaveValue('password123');
  });
});
