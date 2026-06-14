import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID      = process.env.ST_CLIENT_ID;
const CLIENT_SECRET  = process.env.ST_CLIENT_SECRET;
const BASE_URL       = process.env.BASE_URL || `http://localhost:${PORT}`;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'nammaveedu';
const ST_API         = 'https://api.smartthings.com/v1';
const ST_TOKEN_URL   = 'https://api.smartthings.com/oauth/token';
const ST_AUTH_URL    = 'https://api.smartthings.com/oauth/authorize';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Global token store (one login for everyone) ────────────────────────────
let globalTokens = {
  access_token: null,
  refresh_token: null,
  expires_at: 0,
};

async function refreshIfNeeded() {
  if (!globalTokens.refresh_token) throw new Error('not_setup');
  if (Date.now() < globalTokens.expires_at - 60_000) return;
  const creds = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const res = await fetch(ST_TOKEN_URL, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: globalTokens.refresh_token }),
  });
  if (!res.ok) { globalTokens = { access_token: null, refresh_token: null, expires_at: 0 }; throw new Error('Token refresh failed — admin must re-login'); }
  const data = await res.json();
  globalTokens.access_token  = data.access_token;
  globalTokens.refresh_token = data.refresh_token || globalTokens.refresh_token;
  globalTokens.expires_at    = Date.now() + (data.expires_in || 86400) * 1000;
}

async function stFetch(method, urlPath, body) {
  await refreshIfNeeded();
  const res = await fetch(`${ST_API}${urlPath}`, {
    method,
    headers: { 'Authorization': `Bearer ${globalTokens.access_token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || `ST API ${res.status}`);
  return data;
}

// ── Auth state for OAuth flow (uses a temp nonce) ──────────────────────────
let pendingState = null;

// Admin-only: start OAuth (protected by password query param)
app.get('/auth/login', (req, res) => {
  if (req.query.pw !== ADMIN_PASSWORD) return res.status(403).send('Wrong password');
  pendingState = crypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: `${BASE_URL}/callback`,
    scope: 'r:devices:* x:devices:*',
    state: pendingState,
  });
  res.redirect(`${ST_AUTH_URL}?${params}`);
});

// OAuth callback — saves tokens globally
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect('/admin?error=' + encodeURIComponent(error));
  if (state !== pendingState) return res.redirect('/admin?error=state_mismatch');
  try {
    const creds = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const tokenRes = await fetch(ST_TOKEN_URL, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${BASE_URL}/callback`, client_id: CLIENT_ID }),
    });
    if (!tokenRes.ok) throw new Error(await tokenRes.text());
    const data = await tokenRes.json();
    globalTokens = {
      access_token:  data.access_token,
      refresh_token: data.refresh_token,
      expires_at:    Date.now() + (data.expires_in || 86400) * 1000,
    };
    pendingState = null;
    res.redirect('/');
  } catch(e) {
    res.redirect('/admin?error=' + encodeURIComponent(e.message));
  }
});

// ── Status API ─────────────────────────────────────────────────────────────
app.get('/api/auth/status', (req, res) => {
  res.json({ ready: !!globalTokens.refresh_token });
});

// ── AC API (no auth needed — anyone on the URL can control) ───────────────
app.get('/api/devices', async (req, res) => {
  try {
    const data = await stFetch('GET', '/devices');
    const acs = data.items.filter(d =>
      d.components?.some(c => c.capabilities?.some(cap =>
        ['airConditionerMode','thermostatCoolingSetpoint','switch'].includes(cap.id)
      ))
    );
    res.json(acs);
  } catch(e) { res.status(e.message === 'not_setup' ? 503 : 500).json({ error: e.message }); }
});

app.get('/api/devices/:id/status', async (req, res) => {
  try {
    const data = await stFetch('GET', `/devices/${req.params.id}/status`);
    const main = data.components?.main || {};
    res.json({
      switch:      main.switch?.switch?.value,
      mode:        main.airConditionerMode?.airConditionerMode?.value,
      targetTemp:  main.thermostatCoolingSetpoint?.coolingSetpoint?.value,
      currentTemp: main.temperatureMeasurement?.temperature?.value,
      fanMode:     main.airConditionerFanMode?.fanMode?.value,
      humidity:    main.relativeHumidityMeasurement?.humidity?.value,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/devices/:id/command', async (req, res) => {
  const { capability, command, args = [] } = req.body;
  try {
    const data = await stFetch('POST', `/devices/${req.params.id}/commands`,
      { commands: [{ component: 'main', capability, command, arguments: args }] });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`\n🏠  Namma Veedu running at ${BASE_URL}\n`));
