// proxy.js (CommonJS)
const express = require("express");

const app = express();
const PORT = process.env.PORT || 8080;

// Put these ONLY on the proxy server (never in the EXE)
const EBAY_CLIENT_ID = process.env.EBAY_CLIENT_ID;
const EBAY_CLIENT_SECRET = process.env.EBAY_CLIENT_SECRET;

// Simple shared key to prevent random abuse
const PROXY_KEY = process.env.PROXY_KEY;

let tokenCache = { token: null, expiresAt: 0 };

function nowMs() {
  return Date.now();
}

async function getEbayAccessToken() {
  if (!EBAY_CLIENT_ID || !EBAY_CLIENT_SECRET) {
    throw new Error("Missing EBAY_CLIENT_ID / EBAY_CLIENT_SECRET on proxy");
  }

  // Reuse token if valid for > 60s
  if (tokenCache.token && tokenCache.expiresAt - nowMs() > 60_000) {
    return tokenCache.token;
  }

  const basic = Buffer.from(`${EBAY_CLIENT_ID}:${EBAY_CLIENT_SECRET}`).toString("base64");

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    scope: "https://api.ebay.com/oauth/api_scope",
  });

  const resp = await fetch("https://api.ebay.com/identity/v1/oauth2/token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(`eBay token error (${resp.status}): ${JSON.stringify(json)}`);
  }

  tokenCache = {
    token: json.access_token,
    expiresAt: nowMs() + Number(json.expires_in || 0) * 1000,
  };

  return tokenCache.token;
}

// Health check
app.get("/", (req, res) => res.send("OK"));

// Token endpoint (protect it)
app.get("/token", async (req, res) => {
  try {
    const key = req.header("x-proxy-key");
    if (!PROXY_KEY || key !== PROXY_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const token = await getEbayAccessToken();
    res.json({ access_token: token });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.listen(PORT, () => {
  console.log(`Token proxy running on port ${PORT}`);
});
console.log("EBAY_CLIENT_ID length:", (EBAY_CLIENT_ID || "").length);
console.log("EBAY_CLIENT_SECRET length:", (EBAY_CLIENT_SECRET || "").length);

