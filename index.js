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

async function dumpDebugInfo(label) {
  const html = await page.content();
  const url = page.url();
  const inputs = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("input")).map((el) => ({
      type: el.type,
      name: el.name,
      id: el.id,
      placeholder: el.placeholder,
      autocomplete: el.autocomplete,
      className: el.className,
      value: el.value ? el.value.substring(0, 3) + "..." : "",
      hidden: el.hidden,
      display: window.getComputedStyle(el).display,
      visibility: window.getComputedStyle(el).visibility,
      rect: el.getBoundingClientRect(),
    }));
  });
  const buttons = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("button")).map((el) => ({
      text: el.innerText.trim(),
      type: el.type,
      disabled: el.disabled,
      className: el.className,
      rect: el.getBoundingClientRect(),
    }));
  });

  const debug = { url, label, timestamp: new Date().toISOString(), inputs, buttons };
  const filename = "./debug_" + label.replace(/\s+/g, "_") + ".json";
  fs.writeFileSync(filename, JSON.stringify(debug, null, 2));
  fs.writeFileSync("./debug_last_page.html", html);
  console.log("Debug dump saved:", filename);
  return debug;
}

async function findAnyInput(page, criteria) {
  const allInputs = await page.evaluate((crit) => {
    return Array.from(document.querySelectorAll("input, textarea")).map((el) => ({
      type: el.type,
      name: el.name,
      id: el.id,
      placeholder: el.placeholder || "",
      autocomplete: el.autocomplete || "",
      ariaLabel: el.getAttribute("aria-label") || "",
      className: el.className,
      tagName: el.tagName,
    }));
  }, criteria);

  console.log("All inputs found:", JSON.stringify(allInputs, null, 2));

  for (const input of allInputs) {
    const matches =
      (criteria.type && input.type === criteria.type) ||
      (criteria.name && input.name.toLowerCase().includes(criteria.name.toLowerCase())) ||
      (criteria.placeholder && input.placeholder.toLowerCase().includes(criteria.placeholder.toLowerCase())) ||
      (criteria.autocomplete && input.autocomplete.toLowerCase().includes(criteria.autocomplete.toLowerCase())) ||
      (criteria.ariaLabel && input.ariaLabel.toLowerCase().includes(criteria.ariaLabel.toLowerCase()));

    if (matches) {
      const selector = input.id
        ? "#" + input.id
        : input.name
        ? 'input[name="' + input.name + '"]'
        : 'input[placeholder="' + input.placeholder + '"]';
      try {
        const el = await page.waitForSelector(selector, { timeout: 5000 });
        if (el) return { element: el, selector, info: input };
      } catch {}
    }
  }

  if (allInputs.length > 0) {
    const first = allInputs[0];
    const fallbackSel = first.id
      ? "#" + first.id
      : first.name
      ? 'input[name="' + first.name + '"]'
      : "input";
    try {
      const el = await page.waitForSelector(fallbackSel, { timeout: 5000 });
      if (el) return { element: el, selector: fallbackSel, info: first };
    } catch {}
  }

  return null;
}

async function submitForm() {
  const submitted = await page.evaluate(() => {
    const form = document.querySelector("form");
    if (form) {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      return "form_dispatch";
    }

    const buttons = Array.from(document.querySelectorAll("button"));
    const nextBtn = buttons.find(
      (b) =>
        b.innerText.trim() === "Next" ||
        b.innerText.trim() === "Continue" ||
        b.innerText.trim() === "Log In"
    );

    if (nextBtn) {
      const rect = nextBtn.getBoundingClientRect();
      const events = ["mousedown", "mouseup", "click", "pointerdown", "pointerup"];
      events.forEach((type) => {
        nextBtn.dispatchEvent(
          new MouseEvent(type, {
            bubbles: true,
            cancelable: true,
            view: window,
            clientX: rect.left + rect.width / 2,
            clientY: rect.top + rect.height / 2,
            button: 0,
            pointerType: "mouse",
            isPrimary: true,
          })
        );
      });
      return "button_native_events";
    }

    return "none";
  });

  console.log("Submit method:", submitted);
  return submitted !== "none";
}

async function performLogin(email, password) {
  await launchBrowser();

  await page.goto("https://accounts.snapchat.com/accounts/login", {
    waitUntil: "networkidle2",
    timeout: 60000,
  });

  await dumpDebugInfo("page_loaded");

  const userInput = await findAnyInput(page, {
    type: "text",
    name: "username",
    placeholder: "username",
    autocomplete: "username",
  });

  if (!userInput) {
    throw new Error("No input field found at all on the page");
  }

  console.log("Using input:", userInput.selector, userInput.info);
  await userInput.element.click();
  await userInput.element.type(email, { delay: 50 });

  await submitForm();
  await delay(5000);

  await dumpDebugInfo("after_username_submit");

  const passInput = await findAnyInput(page, {
    type: "password",
    name: "password",
    placeholder: "password",
    autocomplete: "current-password",
  });

  if (!passInput) {
    const allInputs = await page.evaluate(() =>
      Array.from(document.querySelectorAll("input")).map((el) => ({
        type: el.type,
        name: el.name,
        id: el.id,
        placeholder: el.placeholder,
      }))
    );
    throw new Error(
      "No password field found. All inputs on page: " + JSON.stringify(allInputs)
    );
  }

  console.log("Found password input:", passInput.selector, passInput.info);
  await passInput.element.click();
  await passInput.element.type(password, { delay: 50 });

  await submitForm();
  await delay(5000);

  await dumpDebugInfo("after_password_submit");

  const twoFAField = await findAnyInput(page, {
    type: "text",
    name: "code",
    placeholder: "code",
  });

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
      await twoFAField.element.type(code, { delay: 100 });
    } else {
      const generic = await findAnyInput(page, { type: "text" });
      if (generic) await generic.element.type(code, { delay: 100 });
    }

    await submitForm();
    await delay(5000);
  }

  const cookies = await page.cookies();
  fs.writeFileSync(COOKIE_PATH, JSON.stringify(cookies, null, 2));

  const url = page.url();
  const loggedIn =
    url.includes("web.snapchat.com") ||
    url.includes("accounts.snapchat.com/accounts/welcome") ||
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
