'use strict';

// /api/netcfg — desktop LAN/network access settings. Admin-only: this
// controls whether the server is reachable beyond loopback.

const express = require('express');
const { requireAdmin, auditReq } = require('../auth');
const { getNetConfig, saveNetConfig, getLanStatus } = require('../netcfg');

const router = express.Router();

// index.js registers a callback so a config change can rebind the LAN
// listener without restarting the process (or touching the loopback server
// the desktop window is using).
let onChange = null;
function setOnChange(fn) {
  onChange = fn;
}

router.get('/', requireAdmin, (req, res) => {
  res.json({ config: getNetConfig(), status: getLanStatus() });
});

router.put('/', requireAdmin, (req, res) => {
  const r = saveNetConfig(req.body || {});
  if (r.error) return res.status(400).json({ error: r.error });
  auditReq(req, 'netcfg.updated', `lan=${r.config.enabled} port=${r.config.port || '-'} cidrs=${r.config.allowCidrs.length}`);
  try {
    onChange?.();
  } catch (e) {
    console.error('[ssloth] LAN listener update failed:', e);
  }
  res.json({ config: r.config });
});

module.exports = { router, setOnChange };
