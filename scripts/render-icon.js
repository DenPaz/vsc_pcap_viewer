/**
 * Renders media/icon.svg to media/icon.png (256×256; the Marketplace needs a
 * PNG of at least 128×128) with the Chromium that playwright-core finds.
 * Set CHROMIUM_PATH to use another Chromium build.
 *
 *   node scripts/render-icon.js
 */
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const MEDIA = path.join(__dirname, "..", "media");

async function main() {
  const svg = fs.readFileSync(path.join(MEDIA, "icon.svg"), "utf8");
  const browser = await chromium.launch(
    process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
  );
  try {
    const page = await browser.newPage({ viewport: { width: 256, height: 256 } });
    await page.setContent(
      `<!DOCTYPE html><html><body style="margin:0;background:transparent">${svg}</body></html>`,
    );
    await page.locator("svg").screenshot({
      path: path.join(MEDIA, "icon.png"),
      omitBackground: true,
    });
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
