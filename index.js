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

const PORT = process.env.PORT || 3000;
const COOKIE_PATH = "./snap_cookies.json";

let browser = null;
let page = null;
let resolve2FA = null;
let reject2FA = null;

async function launchBrowser() {
  if (browser) return;
  browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
  });
  page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });
  await page.setUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
  );

  if (fs.existsSync(COOKIE_PATH)) {
    const cookies = JSON.parse(fs.readFileSync(COOKIE_PATH, "utf-8"));
    await page.setCookie(...cookies);
  }
}

async function performLogin(email, password) {
  await launchBrowser();
  await page.goto("https://accounts.snapchat.com/accounts/login", {
    waitUntil: "networkidle2",
  });

  await page.waitForSelector('input[name="username"]', { visible: true, timeout: 15000 });
  await page.type('input[name="username"]', email, { delay: 50 });
  await page.type('input[name="password"]', password, { delay: 50 });
  await page.click("button[type='submit']");

  // Wait for navigation OR 2FA challenge
  await page.waitForNavigation({ waitUntil: "networkidle2", timeout: 10000 }).catch(() => {});

  // Check if we hit the 2FA page
  const twoFAField = await page.$('input[name="code"]');
  if (twoFAField) {
    // Notify frontend via WebSocket
    broadcast({ event: "2fa_required", message: "Enter the 6-digit code sent to your device" });

    const code = await new Promise((resolve, reject) => {
      resolve2FA = resolve;
      reject2FA = reject;
      setTimeout(() => reject(new Error("2FA timeout")), 120000);
    });

    await page.type('input[name="code"]', code, { delay: 100 });
    await page.click("button[type='submit']");
    await page.waitForNavigation({ waitUntil: "networkidle2", timeout: 15000 });
  }

  // Save cookies
  const cookies = await page.cookies();
  fs.writeFileSync(COOKIE_PATH, JSON.stringify(cookies, null, 2));

  const url = page.url();
  if (url.includes("web.snapchat.com") || url.includes("accounts.snapchat.com/accounts/welcome")) {
    broadcast({ event: "logged_in", message: "Successfully logged in" });
    return { success: true };
  } else {
    throw new Error("Login failed or unexpected redirect");
  }
}

function broadcast(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === 1) client.send(JSON.stringify(data));
  });
}

// HTTP Routes
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing credentials" });

  try {
    const result = await performLogin(email, password);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/2fa", async (req, res) => {
  const { code } = req.body;
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: "Invalid code format" });
  if (resolve2FA) {
    resolve2FA(code);
    resolve2FA = null;
    reject2FA = null;
    res.json({ success: true });
  } else {
    res.status(400).json({ error: "No pending 2FA challenge" });
  }
});

app.get("/api/status", async (req, res) => {
  if (!page) return res.json({ loggedIn: false });
  const url = page.url();
  res.json({ loggedIn: url.includes("web.snapchat.com"), url });
});

// WebSocket handling
wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ event: "connected" }));
});

server.listen(PORT, () => {
  console.log(`SnapBot server running on port ${PORT}`);
});
