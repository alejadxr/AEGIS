import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 60000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['json', { outputFile: 'C:/Users/wilsd/AppData/Local/Temp/claude/C--Users-wilsd-RemoteProjects-Laboratorio-Cayde-6/80fc0627-64a0-4511-a737-d78a5ba152e1/scratchpad/aegis-playwright.json' }]],
  use: {
    headless: true,
    actionTimeout: 15000,
    navigationTimeout: 30000,
  },
});
