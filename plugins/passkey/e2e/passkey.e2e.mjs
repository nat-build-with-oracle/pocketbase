// End-to-end check of the dashboard passkey flow in a real (headless) Chromium with a virtual
// fingerprint authenticator (CDP WebAuthn domain): password login -> /_/passkeys -> add a passkey
// -> sign out -> "Sign in with passkey" -> signed in. Screenshots go to $OUT.
//
//   cd e2e && bun install && \
//   BASE=http://localhost:8090 EMAIL=admin@example.com PASSWORD=... OUT=/tmp/shots bun passkey.e2e.mjs
//
// The server must run on localhost (or set PB_PASSKEY_RP_ID/ORIGINS for the address you use).
import { chromium } from "playwright-core";
import { mkdirSync } from "node:fs";

const BASE = process.env.BASE ?? "http://localhost:8090";
const OUT = process.env.OUT ?? "./shots";
mkdirSync(OUT, { recursive: true });
const step = (m) => console.log(`[e2e] ${m}`);

const browser = await chromium.launch({ executablePath: process.env.CHROME || undefined, headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
const cdp = await page.context().newCDPSession(page);
await cdp.send("WebAuthn.enable", { enableUI: false });
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});

try {
  await page.goto(`${BASE}/_/`);
  await page.waitForSelector("form.auth-with-password-form");
  await page.waitForSelector("#pb-passkey-login button");
  step("login page shows 'Sign in with passkey'");
  await page.screenshot({ path: `${OUT}/1-login.png` });

  await page.fill('input[name="identity"]', process.env.EMAIL);
  await page.fill('input[name="password"]', process.env.PASSWORD);
  await page.click("form.auth-with-password-form button.next");
  await page.waitForSelector("#pb-passkey-link");
  step("password login ok, 'Passkeys' button shown");
  await page.screenshot({ path: `${OUT}/2-dashboard.png` });

  await page.click("#pb-passkey-link");
  await page.waitForURL(/\/_\/passkeys/);
  await page.waitForSelector("text=No passkeys yet");
  await page.fill('input[placeholder^="Name"]', "e2e virtual fingerprint");
  await page.click("text=Add a passkey");
  await page.waitForSelector("text=Passkey added", { timeout: 15000 });
  await page.waitForSelector("text=e2e virtual fingerprint");
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  if (credentials.length !== 1 || !credentials[0].isResidentCredential) throw new Error("authenticator should hold 1 resident credential");
  step(`passkey added (rpId ${credentials[0].rpId})`);
  await page.screenshot({ path: `${OUT}/3-passkey-added.png` });

  await page.evaluate(() => localStorage.clear());
  await page.goto(`${BASE}/_/#/login`);
  await page.waitForSelector("#pb-passkey-login button");
  await page.click("#pb-passkey-login button");
  await page.waitForFunction(() => {
    const s = localStorage.getItem("__pb_superusers__/_");
    return s && JSON.parse(s).token && !location.hash.startsWith("#/login");
  }, undefined, { timeout: 15000 });
  await page.waitForSelector("#pb-passkey-link");
  const who = await page.evaluate(() => JSON.parse(localStorage.getItem("__pb_superusers__/_")).record.email);
  step(`signed out, then signed in with the passkey as ${who}`);
  await page.screenshot({ path: `${OUT}/4-signed-in-by-passkey.png` });

  await page.goto(`${BASE}/_/passkeys`);
  await page.waitForSelector("text=last used");
  step("passkey shows 'last used'");
  await page.screenshot({ path: `${OUT}/5-last-used.png` });

  // a user-verification failure must not sign in
  await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: false });
  await page.evaluate(() => localStorage.clear());
  await page.goto(`${BASE}/_/#/login`);
  await page.click("#pb-passkey-login button");
  await page.waitForSelector("#pb-passkey-login [role=alert]:not(:empty)", { timeout: 15000 });
  const signedIn = await page.evaluate(() => !!localStorage.getItem("__pb_superusers__/_"));
  if (signedIn) throw new Error("signed in without user verification");
  step("no fingerprint/face/PIN: refused, still signed out");
  console.log("[e2e] PASS");
} catch (e) {
  await page.screenshot({ path: `${OUT}/fail.png` });
  console.log("[e2e] FAIL", e.message);
  process.exitCode = 1;
} finally {
  await browser.close();
}
