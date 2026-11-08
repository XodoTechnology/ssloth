'use strict';

// Optional OIDC single-sign-on — entirely env-configured, disabled unless
// SSLOTH_OIDC_ISSUER and SSLOTH_OIDC_CLIENT_ID are both set:
//
//   SSLOTH_OIDC_ISSUER         e.g. https://accounts.google.com or
//                              https://keycloak.example.com/realms/myrealm
//   SSLOTH_OIDC_CLIENT_ID      public or confidential client id
//   SSLOTH_OIDC_CLIENT_SECRET  required for confidential clients
//   SSLOTH_OIDC_REDIRECT_URI   must match the IdP registration; defaults to
//                              <scheme>://<request host>/api/auth/oidc/callback
//   SSLOTH_OIDC_SCOPES         default 'openid profile email'
//   SSLOTH_OIDC_USERNAME_CLAIM claim used as the local username
//                              (default 'preferred_username', falls back to
//                              the local part of 'email')
//   SSLOTH_OIDC_AUTO_PROVISION 'true' creates unknown users on first login
//                              (always role 'user', never admin, and the
//                              account gets a random password hash so local
//                              password login stays disabled)
//
// Flow: /api/auth/oidc/login -> IdP -> /api/auth/oidc/callback. State+nonce+
// PKCE verifier live in a short-lived in-memory map (single-process server).

const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const ISSUER = (process.env.SSLOTH_OIDC_ISSUER || '').replace(/\/+$/, '');
const CLIENT_ID = process.env.SSLOTH_OIDC_CLIENT_ID || '';
const CLIENT_SECRET = process.env.SSLOTH_OIDC_CLIENT_SECRET || '';
const SCOPES = process.env.SSLOTH_OIDC_SCOPES || 'openid profile email';
const AUTO_PROVISION = process.env.SSLOTH_OIDC_AUTO_PROVISION === 'true';
const USERNAME_CLAIM = process.env.SSLOTH_OIDC_USERNAME_CLAIM || 'preferred_username';
const REDIRECT_URI = process.env.SSLOTH_OIDC_REDIRECT_URI || '';

const USERNAME_RE = /^[a-zA-Z0-9_.-]{2,32}$/;
const STATE_TTL_MS = 10 * 60 * 1000;

const enabled = () => !!(ISSUER && CLIENT_ID);

const pending = new Map(); // state -> { nonce, verifier, exp }

let jwks = null;
let discoPromise = null;

async function discovery() {
  if (!discoPromise) {
    discoPromise = (async () => {
      const res = await fetch(`${ISSUER}/.well-known/openid-configuration`);
      if (!res.ok) throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
      const d = await res.json();
      if (!d.authorization_endpoint || !d.token_endpoint || !d.jwks_uri) {
        throw new Error('OIDC discovery document missing endpoints');
      }
      jwks = createRemoteJWKSet(new URL(d.jwks_uri));
      return d;
    })();
    discoPromise.catch(() => { discoPromise = null; });
  }
  return discoPromise;
}

function redirectUri(req) {
  return REDIRECT_URI || `${req.protocol}://${req.get('host')}/api/auth/oidc/callback`;
}

async function startLogin(req, res) {
  const d = await discovery();
  const state = crypto.randomBytes(16).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const now = Date.now();
  for (const [k, v] of pending) if (v.exp < now) pending.delete(k);
  pending.set(state, { nonce, verifier, exp: now + STATE_TTL_MS });

  const u = new URL(d.authorization_endpoint);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', CLIENT_ID);
  u.searchParams.set('redirect_uri', redirectUri(req));
  u.searchParams.set('scope', SCOPES);
  u.searchParams.set('state', state);
  u.searchParams.set('nonce', nonce);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  res.redirect(u.toString());
}

function fail(res, msg) {
  res.redirect(`/login?oidc_error=${encodeURIComponent(msg)}`);
}

// Returns the local username for verified claims, or null when unmappable.
function mapUsername(payload) {
  let name = String(payload[USERNAME_CLAIM] || '');
  if (!USERNAME_RE.test(name) && payload.email) {
    name = String(payload.email).split('@')[0];
  }
  name = name.toLowerCase();
  return USERNAME_RE.test(name) ? name : null;
}

async function finishLogin(req, res, { db, createSession, audit, hashPassword, DUMMY_HASH, isLoopbackClient, lanActive }) {
  const { code, state, error, error_description } = req.query;
  if (error) return fail(res, error_description || error);
  const p = state && pending.get(state);
  if (p) pending.delete(state);
  if (!p || p.exp < Date.now() || !code) return fail(res, 'invalid or expired sign-in state — try again');

  let d;
  try {
    d = await discovery();
  } catch (e) {
    return fail(res, `identity provider unreachable: ${e.message}`);
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: String(code),
    redirect_uri: redirectUri(req),
    client_id: CLIENT_ID,
    code_verifier: p.verifier,
  });
  if (CLIENT_SECRET) body.set('client_secret', CLIENT_SECRET);

  let idToken;
  try {
    const tok = await fetch(d.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body,
    });
    if (!tok.ok) return fail(res, `token exchange failed: HTTP ${tok.status}`);
    idToken = (await tok.json()).id_token;
  } catch {
    return fail(res, 'token exchange failed');
  }
  if (!idToken) return fail(res, 'identity provider returned no id_token');

  let payload;
  try {
    ({ payload } = await jwtVerify(idToken, jwks, { issuer: ISSUER, audience: CLIENT_ID }));
  } catch (e) {
    return fail(res, `id_token verification failed: ${e.message}`);
  }
  if (payload.nonce !== p.nonce) return fail(res, 'nonce mismatch');

  const username = mapUsername(payload);
  if (!username) return fail(res, 'no usable username claim from identity provider');

  let user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);
  if (!user) {
    if (!AUTO_PROVISION) return fail(res, `no local account for '${username}' — ask an admin to create it`);
    const info = db
      .prepare('INSERT INTO users (username, password_hash, is_admin, role) VALUES (?, ?, 0, ?)')
      .run(username, await hashPassword(crypto.randomBytes(24).toString('base64url')), 'user');
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    audit({ id: user.id, username: user.username }, 'auth.oidc_provisioned', `SSO account '${username}' created`, req);
  }

  if (lanActive() && !isLoopbackClient(req) && user.lan_allowed === 0) {
    audit({ id: user.id, username: user.username }, 'auth.login_denied', 'account not allowed from this network', req);
    return fail(res, 'this account cannot sign in from the network');
  }

  createSession(user.id, req, res);
  audit({ id: user.id, username: user.username }, 'auth.oidc_login', `SSO login (${payload.email || username})`, req);
  res.redirect('/');
}

module.exports = { enabled, startLogin, finishLogin };
