# Egress probe

A standalone endpoint that records the source IP of whatever calls it. Deploy it
somewhere the system under test can reach, point that system's outbound
integration at it, and the addresses it logs are that system's egress IPs.

It is deliberately **not** wired into the MedSecure API: it is unauthenticated
by design at the HTTP layer (a caller cannot present our API key), and mounting
a catch-all inside the medical app would shadow real routes.

## Run

```bash
npm install
PROBE_TOKEN=<random> TRUSTED_PROXY_HOPS=<n> PORT=4100 npm start
```

Then have the calling system hit it with `X-Probe-Token: <random>`. Collapse the
results to the candidate set:

```bash
npm run report
```

## TRUSTED_PROXY_HOPS - set this correctly or the output is worthless

Only `req.socket.remoteAddress` is a fact: it is the peer we actually completed
a TCP handshake with. Every `X-Forwarded-For` entry is a *claim* by the hop to
its right, and the leftmost entry is a claim by the original caller, who can put
anything there:

```bash
curl -H 'X-Forwarded-For: 1.2.3.4' https://probe.example.com/
```

Taking the first XFF entry - the common recipe - reports `1.2.3.4`. When the
output of this exercise becomes a customer's firewall allowlist, that is a
stranger writing entries into it. So instead we count hops in from the right and
skip only the proxies we operate:

| Deployment | `TRUSTED_PROXY_HOPS` | Reported address |
|---|---|---|
| Probe directly on a public IP | `0` | the socket peer; XFF ignored entirely |
| One LB/CDN in front | `1` | the last XFF entry (what the LB appended) |
| CDN -> ingress -> probe | `2` | the second-to-last XFF entry |

Set it to the number of hops you actually control. If the chain turns out
shorter than that, the record is marked `trustworthy: false` and `report.js`
labels it `UNTRUSTED - do not ship`, because the address then came from the
caller rather than from our own infrastructure.

`behindProxy` in each record answers "is the probe behind a proxy?" empirically:
a real hop always leaves a header behind. `report.js` flags an INCONSISTENT
result, where only some requests carry XFF - that usually means the probe is
reachable both through the LB and directly, and the direct path should be closed
before trusting anything.

## Locking it down

It is locked by default: with no `PROBE_TOKEN` and no `PROBE_OPEN=1`, every
request 404s, so a half-finished deploy cannot sit open logging strangers.
Unauthenticated requests get 404 rather than 401 so scanners learn nothing.

When the capture is done, stop the process and remove the deployment - the token
gate is there to keep the window small, not to make it safe to leave running.
`observations.jsonl` records third-party IP addresses; it is gitignored, delete
it once the set is confirmed.

## Cross-checking from the calling host

The probe reports what the *receiver* sees. Confirm it independently from the
sending host, since a system can egress differently per destination:

```bash
for i in $(seq 1 20); do curl -s ifconfig.me; echo; done | sort -u
```

A mismatch between the two lists is the finding, not a nuisance: it means source
routing, a per-destination route, or a failover address is in play, and the
config needs to be understood before any list is handed to a customer.
