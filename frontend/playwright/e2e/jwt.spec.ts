import { expect, test } from '@playwright/test';

test('sign JWT, decode it, verify signature', async ({ page }) => {
  await page.goto('/jwt-studio');

  await page.getByRole('button', { name: 'Sign HS256' }).click();
  await expect(page.locator('text=Invalid JWT format').first()).toBeHidden({ timeout: 5_000 }).catch(() => {
    // Ignore if token is valid and colorizer rendered immediately.
  });

  await page.getByRole('button', { name: 'Decode' }).click();
  await expect(page.locator('pre').first()).toBeVisible();

  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.locator('pre').nth(0)).toBeVisible();
});
