import { expect, test } from '@playwright/test';

test('encrypt text and verify decrypted output matches', async ({ page }) => {
  await page.goto('/cipher-playground');

  const textarea = page.locator('textarea').first();
  await textarea.fill('Playwright Cipher Test');

  await page.getByRole('button', { name: 'Encrypt' }).click();
  await expect(page.getByText('Ciphertext:')).toBeVisible();

  await page.getByRole('button', { name: 'Decrypt' }).click();
  await expect(page.getByText('Plaintext: Playwright Cipher Test')).toBeVisible();
});
