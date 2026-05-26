'use strict';
/**
 * AEGIS unified log feed writer (Node.js).
 *
 * Synchronous appendFileSync — atomic up to PIPE_BUF for concurrent writers,
 * never throws (logging must not take down the calling app), drops empty
 * optional fields to keep records compact.
 */
const fs = require('fs');

const DEFAULT_PATH = '/Users/alejandxr/web-logs/aegis-feed.jsonl';

function emit(fields) {
  const { app, src_ip, method, path, status, ...optional } = fields || {};
  const record = {
    ts: new Date().toISOString(),
    app,
    src_ip,
    method,
    path,
    status: Number(status),
  };
  for (const [k, v] of Object.entries(optional)) {
    if (v !== '' && v !== null && v !== undefined) record[k] = v;
  }
  const target = process.env.AEGIS_FEED_PATH || DEFAULT_PATH;
  try {
    fs.appendFileSync(target, JSON.stringify(record) + '\n');
  } catch (_) {
    /* never crash the app */
  }
}

module.exports = { emit };
