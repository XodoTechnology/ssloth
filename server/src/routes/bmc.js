// BMC fleet overview: one call → every BMC host's monitoring state (latest
// sensor sample, host-key status, exclusion flag) for the dashboard page.
const express = require('express');
const db = require('../db');
const sensorsPoll = require('../sensors-poll');

const router = express.Router();

router.get('/overview', (req, res) => {
  const hosts = db
    .prepare("SELECT id, name, hostname, sensor_exclude, hostkey_status, hostkey_checked_at FROM hosts WHERE protocol = 'bmc' AND (user_id = ? OR shared = 1) ORDER BY name COLLATE NOCASE")
    .all(req.user.id);
  res.json({
    hosts: hosts.map((h) => ({
      ...h,
      sensor_exclude: !!h.sensor_exclude,
      latest: sensorsPoll.latest(h.id) || null,
    })),
  });
});

module.exports = router;
