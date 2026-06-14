import express from 'express';
import fetch from 'node-fetch';
import cookieSession from 'cookie-session';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID     = process.env.ST_CLIENT_ID;
const CLIENT_SECRET = process.env.ST_CLIENT_SECRET;
const BASE_URL      = process.env.BASE_URL || `http://localhost:${PORT}`;
const SESSION_SECRET= process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ST_API        = 'https://api.smartthings.com/v1';
const ST_TOKEN_URL  = 'https://api.smartthings.com/oauth/token';
const ST_AUTH_URL   = 'https://api.smartthings.com/oauth/authorize';

app.use(express.json());
app.use(cookieSession({
  name: 'nv_session',
  secret: SESSION_SECRET,
  maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── helpers ────────────────────────────────────────────────────────────────

async function refreshIfNeeded(session) {
  if (!session.refresh_token) throw new Error('Not logged in');
  const expiresAt = session.expires_at || 0;
  if (Date.now() < expiresAt - 60_000) return; // still valid
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: session.refresh_token,
  });
  const creds = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const res = await fetch(ST_TOKEN_URL, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Token refresh failed: ${t}`);
  }
  const data = await res.json();
  session.access_token  = data.access_token;
  session.refresh_token = data.refresh_token || session.refresh_token;
  session.expires_at    = Date.now() + (data.expires_in || 86400) * 1000;
}

async function stFetch(session, method, urlPath, body) {
  await refreshIfNeeded(session);
  const res = await fetch(`${ST_API}${urlPath}`, {
    method,
    headers: { 'Authorization': `Bearer ${session.access_token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || `ST API ${res.status}`);
  return data;
}

function requireAuth(req, res, next) {
  if (!req.session?.access_token) return res.status(401).json({ error: 'not_logged_in' });
  next();
}

// ── OAuth routes ───────────────────────────────────────────────────────────

// Start OAuth login
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauth_state = state;
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: `${BASE_URL}/callback`,
    scope: 'r:devices:* x:devices:*',
    state,
  });
  res.redirect(`${ST_AUTH_URL}?${params}`);
});

// OAuth callback
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect('/?error=' + encodeURIComponent(error));
  if (state !== req.session.oauth_state) return res.redirect('/?error=state_mismatch');

  try {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${BASE_URL}/callback`,
      client_id: CLIENT_ID,
    });
    const creds = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const tokenRes = await fetch(ST_TOKEN_URL, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });
    if (!tokenRes.ok) throw new Error(await tokenRes.text());
    const data = await tokenRes.json();

    req.session.access_token  = data.access_token;
    req.session.refresh_token = data.refresh_token;
    req.session.expires_at    = Date.now() + (data.expires_in || 86400) * 1000;
    req.session.oauth_state   = null;

    res.redirect('/');
  } catch (e) {
    res.redirect('/?error=' + encodeURIComponent(e.message));
  }
});

// Logout
app.get('/auth/logout', (req, res) => {
  req.session = null;
  res.redirect('/');
});

// Auth status check
app.get('/api/auth/status', (req, res) => {
  res.json({ loggedIn: !!req.session?.access_token });
});

// ── AC API routes ──────────────────────────────────────────────────────────

app.get('/api/devices', requireAuth, async (req, res) => {
  try {
    const data = await stFetch(req.session, 'GET', '/devices');
    const acs = data.items.filter(d =>
      d.components?.some(c =>
        c.capabilities?.some(cap =>
          ['airConditionerMode', 'thermostatCoolingSetpoint', 'switch'].includes(cap.id)
        )
      )
    );
    res.json(acs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/devices/:id/status', requireAuth, async (req, res) => {
  try {
    const data = await stFetch(req.session, 'GET', `/devices/${req.params.id}/status`);
    const main = data.components?.main || {};
    res.json({
      switch:      main.switch?.switch?.value,
      mode:        main.airConditionerMode?.airConditionerMode?.value,
      targetTemp:  main.thermostatCoolingSetpoint?.coolingSetpoint?.value,
      currentTemp: main.temperatureMeasurement?.temperature?.value,
      fanMode:     main.airConditionerFanMode?.fanMode?.value,
      humidity:    main.relativeHumidityMeasurement?.humidity?.value,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/devices/:id/command', requireAuth, async (req, res) => {
  const { capability, command, args = [] } = req.body;
  if (!capability || !command) return res.status(400).json({ error: 'capability and command required' });
  try {
    const body = { commands: [{ component: 'main', capability, command, arguments: args }] };
    const data = await stFetch(req.session, 'POST', `/devices/${req.params.id}/commands`, body);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`\n🏠  Namma Veedu AC running at ${BASE_URL}\n`));
