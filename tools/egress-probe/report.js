const fs = require('fs');
const path = require('path');

// Collapses observations.jsonl into the deduped candidate egress set (step 4).
// Reads the JSONL rather than console output so a rolled or interleaved log
// cannot silently drop samples from the set.

const LOG_PATH = process.argv[2] || process.env.PROBE_LOG ||
  path.join(__dirname, 'observations.jsonl');

if (!fs.existsSync(LOG_PATH)) {
  console.error(`No log at ${LOG_PATH} - nothing has called the probe yet.`);
  process.exit(1);
}

const rows = fs.readFileSync(LOG_PATH, 'utf8')
  .split('\n').filter(Boolean).map(line => JSON.parse(line));

const byIP = new Map();
for (const r of rows) {
  const e = byIP.get(r.sourceIP) || { count: 0, first: r.at, last: r.at, trustworthy: true };
  e.count++;
  e.last = r.at;
  e.trustworthy = e.trustworthy && r.trustworthy;
  byIP.set(r.sourceIP, e);
}

const proxied = rows.filter(r => r.behindProxy).length;
console.log(`samples: ${rows.length}   unique source IPs: ${byIP.size}`);
console.log(`behind a proxy: ${proxied === 0 ? 'no (no X-Forwarded-For seen)'
  : proxied === rows.length ? 'yes (every request carried X-Forwarded-For)'
  : `INCONSISTENT - ${proxied}/${rows.length} requests carried X-Forwarded-For`}`);
console.log('');
for (const [ip, e] of [...byIP.entries()].sort((a, b) => b[1].count - a[1].count)) {
  console.log(`  ${ip}\t${e.count} hit(s)\t${e.first} .. ${e.last}` +
    `${e.trustworthy ? '' : '\tUNTRUSTED - do not ship'}`);
}

// A single sample proves nothing about a fleet: with N instances behind a
// round robin, the chance of missing one grows with N. Say so rather than
// letting a short run read as a complete set.
if (rows.length < 20) {
  console.log(`\nOnly ${rows.length} sample(s). Fire 20+ before treating this as the full set.`);
}
