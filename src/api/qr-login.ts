// QR Code Login Landing Page
// When users scan a QR code, they're directed here to complete login

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { hashToken } from '../utils/crypto';

const app = new Hono<AppEnv>();

// Generate the landing page HTML
function generateQrLandingPage(
  serverName: string,
  token: string,
  userId: string,
  expiresAt: number
): string {
  const expiresInMinutes = Math.max(0, Math.ceil((expiresAt - Date.now()) / 60000));

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login to ${serverName}</title>
  <style>
    :root {
      --primary: #0d9488;
      --primary-dark: #0f766e;
      --bg: #0f172a;
      --bg-card: #1e293b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --border: #334155;
      --success: #22c55e;
      --warning: #f59e0b;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }

    .container {
      background: var(--bg-card);
      border-radius: 16px;
      padding: 40px;
      max-width: 420px;
      width: 100%;
      text-align: center;
      border: 1px solid var(--border);
    }

    .logo {
      font-size: 64px;
      margin-bottom: 20px;
    }

    h1 {
      font-size: 24px;
      margin-bottom: 8px;
    }

    .server-name {
      color: var(--primary);
      font-size: 14px;
      margin-bottom: 24px;
    }

    .user-info {
      background: var(--bg);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
    }

    .user-info label {
      font-size: 12px;
      color: var(--text-muted);
      display: block;
      margin-bottom: 4px;
    }

    .user-info .value {
      font-size: 16px;
      word-break: break-all;
    }

    .expiry {
      font-size: 13px;
      color: var(--warning);
      margin-bottom: 24px;
    }

    .btn {
      display: block;
      width: 100%;
      padding: 14px 20px;
      border-radius: 8px;
      border: none;
      font-size: 16px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      margin-bottom: 12px;
      transition: all 0.2s;
    }

    .btn-primary {
      background: var(--primary);
      color: white;
    }

    .btn-primary:hover {
      background: var(--primary-dark);
    }

    .btn-secondary {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
    }

    .btn-secondary:hover {
      background: var(--border);
    }

    .divider {
      display: flex;
      align-items: center;
      margin: 24px 0;
      color: var(--text-muted);
      font-size: 13px;
    }

    .divider::before,
    .divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }

    .divider span {
      padding: 0 16px;
    }

    .manual-section {
      text-align: left;
      background: var(--bg);
      border-radius: 8px;
      padding: 16px;
    }

    .manual-section h3 {
      font-size: 14px;
      margin-bottom: 12px;
      color: var(--text-muted);
    }

    .copy-field {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
    }

    .copy-field input {
      flex: 1;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      color: var(--text);
      font-size: 13px;
      font-family: monospace;
    }

    .copy-field button {
      background: var(--border);
      border: none;
      border-radius: 6px;
      padding: 10px 14px;
      color: var(--text);
      cursor: pointer;
      font-size: 13px;
    }

    .copy-field button:hover {
      background: var(--primary);
    }

    .status {
      margin-top: 20px;
      padding: 12px;
      border-radius: 8px;
      font-size: 14px;
    }

    .status.success {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
    }

    .status.error {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .hidden {
      display: none;
    }

    .apps {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 16px;
    }

    .app-btn {
      padding: 12px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      text-decoration: none;
      color: var(--text);
      font-size: 13px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
    }

    .app-btn:hover {
      border-color: var(--primary);
    }

    .app-btn .icon {
      font-size: 24px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">🔐</div>
    <h1>Welcome!</h1>
    <div class="server-name">${serverName}</div>

    <div class="user-info">
      <label>Logging in as</label>
      <div class="value">${userId}</div>
    </div>

    <div class="expiry" id="expiry">
      Token expires in ${expiresInMinutes} minute${expiresInMinutes !== 1 ? 's' : ''}
    </div>

    <button class="btn btn-primary" onclick="openInElement()">
      Open in Element
    </button>

    <div class="apps">
      <a href="https://app.element.io/#/login" class="app-btn" target="_blank">
        <span class="icon">🌐</span>
        <span>Element Web</span>
      </a>
      <a href="https://play.google.com/store/apps/details?id=im.vector.app" class="app-btn" target="_blank">
        <span class="icon">🤖</span>
        <span>Android</span>
      </a>
      <a href="https://apps.apple.com/app/element-messenger/id1083446067" class="app-btn" target="_blank">
        <span class="icon">🍎</span>
        <span>iOS</span>
      </a>
      <a href="https://element.io/download" class="app-btn" target="_blank">
        <span class="icon">💻</span>
        <span>Desktop</span>
      </a>
    </div>

    <div class="divider"><span>or login manually</span></div>

    <div class="manual-section">
      <h3>Manual Login Details</h3>
      <div class="copy-field">
        <input type="text" value="https://${serverName}" readonly id="homeserverUrl">
        <button onclick="copyField('homeserverUrl')">Copy</button>
      </div>
      <div class="copy-field">
        <input type="text" value="${token}" readonly id="loginToken">
        <button onclick="copyField('loginToken')">Copy</button>
      </div>
      <p style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">
        In Element: Settings → Advanced → "Log in with token"
      </p>
    </div>

    <div id="status" class="status hidden"></div>
  </div>

  <script>
    const token = "${token}";
    const homeserver = "https://${serverName}";
    const expiresAt = ${expiresAt};

    // Update expiry timer
    function updateExpiry() {
      const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 60000));
      const el = document.getElementById('expiry');
      if (remaining <= 0) {
        el.textContent = 'Token has expired';
        el.style.color = '#ef4444';
      } else {
        el.textContent = 'Token expires in ' + remaining + ' minute' + (remaining !== 1 ? 's' : '');
      }
    }
    setInterval(updateExpiry, 30000);

    function copyField(id) {
      const input = document.getElementById(id);
      input.select();
      document.execCommand('copy');
      showStatus('Copied to clipboard!', 'success');
    }

    function showStatus(message, type) {
      const el = document.getElementById('status');
      el.textContent = message;
      el.className = 'status ' + type;
      setTimeout(() => {
        el.className = 'status hidden';
      }, 3000);
    }

    function openInElement() {
      // Try to open Element with the login token
      // Element Web doesn't have direct token login URL, but we can try
      const elementWebUrl = 'https://app.element.io/#/login';

      // For mobile, try deep links
      const userAgent = navigator.userAgent.toLowerCase();

      if (/iphone|ipad|ipod/.test(userAgent)) {
        // iOS - try Element app deep link
        window.location.href = 'element://';
        setTimeout(() => {
          window.location.href = 'https://apps.apple.com/app/element-messenger/id1083446067';
        }, 2000);
      } else if (/android/.test(userAgent)) {
        // Android - try Element app deep link
        window.location.href = 'element://';
        setTimeout(() => {
          window.location.href = 'https://play.google.com/store/apps/details?id=im.vector.app';
        }, 2000);
      } else {
        // Desktop - open Element Web
        window.open(elementWebUrl, '_blank');
        showStatus('Opening Element Web. Use the token above to log in.', 'success');
      }
    }

    // Auto-attempt login on mobile
    if (/mobile|android|iphone|ipad/i.test(navigator.userAgent)) {
      // On mobile, show a prompt to open the app
      document.querySelector('.btn-primary').textContent = 'Open Element App';
    }
  </script>
</body>
</html>`;
}

// Landing page for QR code login
app.get('/login/qr/:token', async (c) => {
  const token = c.req.param('token');

  // Validate token format
  if (!token || !token.startsWith('mlt_')) {
    return c.html(`<!DOCTYPE html>
<html><head><title>Invalid Token</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0f172a;color:#f1f5f9;}
.error{text-align:center;padding:40px;background:#1e293b;border-radius:12px;border:1px solid #334155;}
h1{color:#ef4444;}</style></head>
<body><div class="error"><h1>Invalid Token</h1><p>This login link is invalid or has been tampered with.</p></div></body></html>`, 400);
  }

  // Look up the token
  const tokenHash = await hashToken(token);
  const tokenData = await c.env.SESSIONS.get(`login_token:${tokenHash}`, 'json') as {
    user_id: string;
    expires_at: number;
  } | null;

  if (!tokenData) {
    return c.html(`<!DOCTYPE html>
<html><head><title>Token Expired</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0f172a;color:#f1f5f9;}
.error{text-align:center;padding:40px;background:#1e293b;border-radius:12px;border:1px solid #334155;}
h1{color:#f59e0b;}</style></head>
<body><div class="error"><h1>Token Expired</h1><p>This login link has expired or has already been used.</p><p>Please request a new QR code from your administrator.</p></div></body></html>`, 400);
  }

  // Check if expired
  if (Date.now() > tokenData.expires_at) {
    // Clean up
    await c.env.SESSIONS.delete(`login_token:${tokenHash}`);
    return c.html(`<!DOCTYPE html>
<html><head><title>Token Expired</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0f172a;color:#f1f5f9;}
.error{text-align:center;padding:40px;background:#1e293b;border-radius:12px;border:1px solid #334155;}
h1{color:#f59e0b;}</style></head>
<body><div class="error"><h1>Token Expired</h1><p>This login link has expired.</p><p>Please request a new QR code from your administrator.</p></div></body></html>`, 400);
  }

  // Show the landing page
  return c.html(generateQrLandingPage(
    c.env.SERVER_NAME,
    token,
    tokenData.user_id,
    tokenData.expires_at
  ));
});

// API endpoint to check token validity (for JS-based login)
app.get('/login/qr/:token/check', async (c) => {
  const token = c.req.param('token');

  if (!token || !token.startsWith('mlt_')) {
    return c.json({ valid: false, error: 'Invalid token format' }, 400);
  }

  const tokenHash = await hashToken(token);
  const tokenData = await c.env.SESSIONS.get(`login_token:${tokenHash}`, 'json') as {
    user_id: string;
    expires_at: number;
  } | null;

  if (!tokenData) {
    return c.json({ valid: false, error: 'Token not found or expired' }, 404);
  }

  if (Date.now() > tokenData.expires_at) {
    return c.json({ valid: false, error: 'Token expired' }, 400);
  }

  return c.json({
    valid: true,
    user_id: tokenData.user_id,
    homeserver: c.env.SERVER_NAME,
    expires_at: tokenData.expires_at,
  });
});

export default app;
