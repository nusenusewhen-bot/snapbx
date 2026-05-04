import puppeteer from "puppeteer-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import express from "express";
import { WebSocketServer } from "ws";
import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

puppeteer.use(StealthPlugin());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 8080;
const COOKIE_PATH = "./snap_cookies.json";

let browser = null;
let page = null;
let resolve2FA = null;
let reject2FA = null;

async function launchBrowser() {
  if (browser) return;
  browser = await puppeteer.launch({
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-accelerated-2d-canvas",
      "--disable-gpu",
      "--window-size=1920,1080",
    ],
  });
  page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });
  await page.setUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
  );

  if (fs.existsSync(COOKIE_PATH)) {
    try {
      const cookies = JSON.parse(fs.readFileSync(COOKIE_PATH, "utf-8"));
      await page.setCookie(...cookies);
      console.log("Loaded existing cookies");
    } catch (e) {
      console.error("Cookie load error:", e.message);
    }
  }
}

async function clickNextButton() {
  const nextSelectors = [
    "button:has-text('Next')",
    "button[type='submit']",
    'button[data-testid*="next" i]',
    'button[data-testid*="submit" i]',
    "button:has-text('Continue')",
    "button:has-text('Log In')",
    "button:has-text('Sign In')",
  ];

  for (const sel of nextSelectors) {
    try {
      const btn = await page.waitForSelector(sel, { timeout: 3000, visible: true });
      if (btn) {
        await btn.click();
        console.log("Clicked button via:", sel);
        return true;
      }
    } catch {}
  }

  const fallback = await page.evaluate(() => {
    const buttons = Array.from(document.querySelectorAll("button"));
    const nextBtn = buttons.find(
      (b) =>
        b.innerText.includes("Next") ||
        b.innerText.includes("Continue") ||
        b.innerText.includes("Log In")
    );
    if (nextBtn) {
      nextBtn.click();
      return true;
    }
    return false;
  });

  return fallback;
}

async function performLogin(email, password) {
  await launchBrowser();

  await page.goto("https://accounts.snapchat.com/accounts/login", {
    waitUntil: "networkidle2",
    timeout: 60000,
  });

  await page.waitForFunction(
    () => document.querySelectorAll("input").length >= 1,
    { timeout: 15000 }
  );

  const usernameSelectors = [
    'input[name="username"]',
    'input[name="identifier"]',
    'input[name="accountIdentifier"]',
    'input[autocomplete="username"]',
    'input[type="text"]',
    'input[placeholder*="username" i]',
    'input[placeholder*="email" i]',
    'input[placeholder*="phone" i]',
    'input#username',
    'input#identifier',
  ];

  let userField = null;
  let userSel = null;

  for (const sel of usernameSelectors) {
    try {
      userField = await page.waitForSelector(sel, { timeout: 5000, visible: true });
      if (userField) {
        userSel = sel;
        break;
      }
    } catch {}
  }

  if (!userField) {
    throw new Error("Could not find username/email input field");
  }

  console.log("Found username field via:", userSel);
  await userField.type(email, { delay: 50 });

  const navPromise1 = page
    .waitForNavigation({ waitUntil: "networkidle2", timeout: 20000 })
    .catch(() => {});

  const clicked1 = await clickNextButton();
  if (!clicked1) {
    await page.keyboard.press("Enter");
  }

  await navPromise1;
  await delay(3000);

  const passwordSelectors = [
    'input[name="password"]',
    'input[type="password"]',
    'input[autocomplete="current-password"]',
    'input[placeholder*="password" i]',
    'input#password',
  ];

  let passField = null;
  let passSel = null;

  for (const sel of passwordSelectors) {
    try {
      passField = await page.waitForSelector(sel, { timeout: 8000, visible: true });
      if (passField) {
        passSel = sel;
        break;
      }
    } catch {}
  }

  if (!passField) {
    throw new Error("Could not find password input field — may still be on username page");
  }

  console.log("Found password field via:", passSel);
  await passField.type(password, { delay: 50 });

  const navPromise2 = page
    .waitForNavigation({ waitUntil: "networkidle2", timeout: 20000 })
    .catch(() => {});

  const clicked2 = await clickNextButton();
  if (!clicked2) {
    await page.keyboard.press("Enter");
  }

  await navPromise2;
  await delay(3000);

  const twoFASelectors = [
    'input[name="code"]',
    'input[name="otp"]',
    'input[name="verificationCode"]',
    'input[type="text"][maxlength="6"]',
    'input[autocomplete="one-time-code"]',
    'input[placeholder*="code" i]',
    'input#code',
    'input#otp',
  ];

  let twoFAField = null;

  for (const sel of twoFASelectors) {
    try {
      twoFAField = await page.waitForSelector(sel, { timeout: 3000, visible: true });
      if (twoFAField) break;
    } catch {}
  }

  const pageText = await page.evaluate(() => document.body.innerText);
  const is2FAPage =
    twoFAField ||
    /verification code|two.factor|2fa|authenticate|security code/i.test(pageText);

  if (is2FAPage) {
    broadcast({
      event: "2fa_required",
      message: "Enter the 6-digit code sent to your device",
    });

    const code = await new Promise((resolve, reject) => {
      resolve2FA = resolve;
      reject2FA = reject;
      setTimeout(() => reject(new Error("2FA timeout — 120s expired")), 120000);
    });

    if (twoFAField) {
      await twoFAField.type(code, { delay: 100 });
    } else {
      const genericInput = await page.$('input[type="text"]');
      if (genericInput) await genericInput.type(code, { delay: 100 });
    }

    const navPromise3 = page
      .waitForNavigation({ waitUntil: "networkidle2", timeout: 20000 })
      .catch(() => {});

    const clicked3 = await clickNextButton();
    if (!clicked3) {
      await page.keyboard.press("Enter");
    }

    await navPromise3;
  }

  const cookies = await page.cookies();
  fs.writeFileSync(COOKIE_PATH, JSON.stringify(cookies, null, 2));

  const url = page.url();
  const loggedIn =
    url.includes("web.snapchat.com") ||
    url.includes("accounts.snapchat.com/accounts/welcome") ||
    url.includes("accounts.snapchat.com/accounts/v2") ||
    !url.includes("login");

  if (loggedIn) {
    broadcast({ event: "logged_in", message: "Successfully logged in" });
    return { success: true, url };
  } else {
    const errorText = await page.evaluate(() => {
      const err = document.querySelector('[role="alert"], .error, .Error');
      return err ? err.innerText : "";
    });
    throw new Error(
      "Login failed. URL: " + url + ". " + (errorText ? "Error: " + errorText : "")
    );
  }
}

function broadcast(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(JSON.stringify(data));
    }
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  try {
    const result = await performLogin(email, password);
    res.json(result);
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/2fa", async (req, res) => {
  const { code } = req.body;
  if (!/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: "Invalid code format — must be 6 digits" });
  }
  if (!resolve2FA) {
    return res.status(400).json({ error: "No pending 2FA challenge" });
  }

  resolve2FA(code);
  resolve2FA = null;
  reject2FA = null;
  res.json({ success: true });
});

app.get("/api/status", async (req, res) => {
  if (!page) return res.json({ loggedIn: false, url: null });
  const url = page.url();
  res.json({
    loggedIn: url.includes("web.snapchat.com"),
    url,
    browserOpen: !!browser,
  });
});

app.post("/api/logout", async (req, res) => {
  if (browser) {
    await browser.close();
    browser = null;
    page = null;
  }
  if (fs.existsSync(COOKIE_PATH)) {
    fs.unlinkSync(COOKIE_PATH);
  }
  res.json({ success: true });
});

app.get("/api/debug/screenshot", async (req, res) => {
  if (!page) return res.status(400).json({ error: "No active page" });
  const buffer = await page.screenshot({ encoding: "base64", fullPage: true });
  res.json({ screenshot: buffer });
});

app.get("/api/debug/html", async (req, res) => {
  if (!page) return res.status(400).json({ error: "No active page" });
  const html = await page.content();
  res.type("html").send(html);
});

wss.on("connection", (ws) => {
  console.log("WebSocket client connected");
  ws.send(JSON.stringify({ event: "connected" }));

  ws.on("close", () => {
    console.log("WebSocket client disconnected");
  });
});

server.listen(PORT, () => {
  console.log("SnapBot server running on http://localhost:" + PORT);
});
