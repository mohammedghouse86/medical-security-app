const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Standalone "vendor endpoint" used to observe which source IP a caller
// egresses from. It is NOT part of the MedSecure API and must not be mounted
// into it: run it separately, on a host the system under test can reach, and
// point that system's outbound integration at it.
//
// Attributing the source IP correctly is the entire job of this app, so the
// header handling below is deliberate rather than the usual one-liner. The
// reasoning is in NOTES.md - read it before trusting any address this logs.

const app = express();
app.disable('x-powered-by');

// How many proxy hops sit in front of THIS app that we operate and therefore
// trust (load balancer, CDN, ingress controller). 0 = directly exposed.
// Getting this number wrong is the difference between a fact and a guess.
const TRUSTED_HOPS = Number.parseInt(process.env.TRUSTED_PROXY_HOPS || '0', 10);
const TOKEN = process.env.PROBE_TOKEN || '';
const OPEN = process.env.PROBE_OPEN === '1';
const LOG_PATH = process.env.PROBE_LOG || path.join(__dirname, 'observations.jsonl');

// Node reports IPv4 peers on a dual-stack socket as ::ffff:a.b.c.d, and an
// unnormalised chain dedupes into two entries for one address.
const normalize = ip => String(ip || '').replace(/^::ffff:/i, '').trim();

// Resolve the caller's address from the observed hop chain.
//
// Only req.socket.remoteAddress is a fact - it is the peer we are actually
// speaking TCP to. Every X-Forwarded-For entry is a *claim* made by the hop to
// its right, and the leftmost entry is a claim made by the original caller,
// who can write anything there. Taking chain[0] therefore returns attacker-
// controlled text, which is exactly what you must not do when the output is
// going to become a customer's firewall allowlist.
//
// Walking in from the right skips the hops we vouch for and stops at the first
// address none of our own infrastructure appended.
function attribute(req) {
  const raw = req.headers['x-forwarded-for'];
  const forwarded = (Array.isArray(raw) ? raw.join(',') : raw || '')
    .split(',').map(normalize).filter(Boolean);
  const socket = normalize(req.socket.remoteAddress);
  const chain = [...forwarded, socket];          // oldest hop first
  const index = chain.length - 1 - TRUSTED_HOPS;
  return {
    sourceIP: chain[Math.max(index, 0)],
    // False when TRUSTED_PROXY_HOPS claims more hops than actually appeared:
    // the chain ran out, so the address above is caller-supplied, not observed.
    trustworthy: index >= 0,
    // Empirical answer to "is this app behind a proxy?" - a real hop in front
    // of us always leaves a header behind.
    behindProxy: forwarded.length > 0,
    chain
  };
}

// Constant-time compare so the token cannot be recovered a byte at a time.
function tokenMatches(presented) {
  const a = Buffer.from(String(presented), 'utf8');
  const b = Buffer.from(TOKEN, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Locked down by default. With no PROBE_TOKEN set the app serves nothing at
// all, so an unfinished deploy cannot sit open on the internet logging
// strangers. PROBE_OPEN=1 is the explicit, deliberate opt-out.
// 404 rather than 401: a scanner that guesses wrong learns nothing about what
// this host is running.
app.use((req, res, next) => {
  if (OPEN) return next();
  if (!TOKEN || !tokenMatches(req.get('X-Probe-Token') || req.query.t || '')) {
    return res.status(404).type('text/plain').send('Not Found');
  }
  next();
});

// Express 5 removed the '*' path string - it throws at registration. A RegExp
// is the unambiguous spelling of a catch-all across both 4 and 5.
app.all(/.*/, (req, res) => {
  const seen = attribute(req);
  const record = {
    at: new Date().toISOString(),
    method: req.method,
    path: req.originalUrl,
    sourceIP: seen.sourceIP,
    trustworthy: seen.trustworthy,
    behindProxy: seen.behindProxy,
    chain: seen.chain,
    trustedHops: TRUSTED_HOPS,
    userAgent: req.get('user-agent') || null
  };
  // Append to a JSONL file as well as stdout: deduping the candidate set by
  // scraping console text is fragile, and hosted platforms roll logs away.
  fs.appendFile(LOG_PATH, JSON.stringify(record) + '\n', err => {
    if (err) console.error('[probe] could not write log:', err.message);
  });
  console.log(`[inbound] source IP: ${record.sourceIP}` +
    `${record.trustworthy ? '' : ' (UNTRUSTED - hop chain shorter than TRUSTED_PROXY_HOPS)'}` +
    ` chain=[${record.chain.join(' <- ')}]`);
  res.json({ seenSourceIP: record.sourceIP, trustworthy: record.trustworthy, chain: record.chain });
});

const port = process.env.PORT || 4100;
app.listen(port, () => {
  console.log(`[probe] listening on ${port}, trusting ${TRUSTED_HOPS} proxy hop(s), log -> ${LOG_PATH}`);
  if (OPEN) console.warn('[probe] PROBE_OPEN=1 - this endpoint is unauthenticated');
  else if (!TOKEN) console.warn('[probe] no PROBE_TOKEN set - every request will 404');
});
