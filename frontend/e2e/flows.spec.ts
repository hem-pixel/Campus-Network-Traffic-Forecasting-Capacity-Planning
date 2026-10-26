import { expect, test } from '@playwright/test';

test('public landing opens a visibly synthetic, read-only demo', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: /Plan capacity with confidence/i })).toBeVisible();
  await page.getByRole('button', { name: /Try the demo/i }).click();
  await expect(page.getByText('DEMO DATA - SYNTHETIC').first()).toBeVisible();
  await expect(page.getByText('DEMO DATA - SYNTHETIC').last()).toBeVisible();
  await page.getByRole('button', { name: 'Connected devices' }).click();
  await expect(page.getByText(/to be recorded/i).first()).toBeVisible();
});

test('sign in page is reachable and labels required fields', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByLabel('Work email')).toBeVisible();
  await expect(page.getByLabel('Password')).toBeVisible();
});
