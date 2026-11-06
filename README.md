# digdiff

Compare what your DNS resolvers think about a domain — straight from the wire.

`dig` talks to one resolver. **digdiff** talks to all of them:
your system's DNS servers, the public ones (Cloudflare, Google, Quad9, …),
and DoH endpoints — then cross-checks every answer against the
**authoritative nameservers** of the zone itself and flags anything that
doesn't add up.

No dependencies. The DNS wire protocol (RFC 1035), TCP fallback (RFC 7766),
EDNS0 and DoH (RFC 8484) are all implemented from scratch in `src/`.

```
node bin/digdiff.js github.com
```

```
ground truth (authoritative): 140.82.121.3 140.82.121.4

github.com  A
resolver           operator       verdict  rcode    latency  answers
-----------------  -------------  -------  -------  -------  ------------  ----------
sys:10.98.255.124  system         agree    NOERROR  55.6ms   140.82.121.4
sys:172.22.252.86  system         agree    NOERROR  55.7ms   140.82.121.4
sys:10.5.240.12    system         agree    NOERROR  43.6ms   140.82.121.3
sys:10.5.240.3     system         agree    NOERROR  44.6ms   140.82.121.3
cloudflare         Cloudflare     agree    NOERROR  53.8ms   140.82.121.4
google             Google         agree    NOERROR  57.6ms   140.82.121.3
quad9              Quad9          differ   NOERROR  71.6ms   4.225.11.194  ≠ 140.82.121.3
opendns            Cisco OpenDNS  agree    NOERROR  57.5ms   140.82.121.3
control-d          Control D      agree    NOERROR  73.8ms   140.82.121.3

✗ 1 resolver(s) disagree with the majority
```

That run is real. On a campus network, Quad9 **intermittently** answers
`github.com` with `4.225.11.194` — a Microsoft Azure address in Sweden —
while the zone's own nameservers and every other resolver say
`140.82.121.3/.4` (GitHub's real range, `140.82.112.0/20`). Run it a few
times and it shows up roughly every third run. That's the point: resolvers
are usually honest, and when they're not, you want to catch it yourself.

## Why does this matter?

DNS answers are generally taken on faith. You ask a resolver, it answers,
your browser connects. But answers can disagree:

- your **ISP or network** rewrites answers (filtering, "captive" portals, sometimes worse)
- a resolver is **misconfigured** or has a poisoned cache
- an **NXDOMAIN hijacker** answers for domains that shouldn't exist
  (a classic ad/malware-blocking shortcut — or a phishing vector)

digdiff surfaces all of it: it asks many independent sources, asks the
**authoritative nameservers** what they actually serve, and calls out every
answer that nobody else corroborates.

## Install & run

```sh
git clone https://github.com/arseniytech/digdiff
cd digdiff
node bin/digdiff.js example.com          # A record, all resolvers
node bin/digdiff.js example.com --doh    # + Cloudflare/Google/Quad9/AdGuard DoH
node bin/digdiff.js example.com --type AAAA
node bin/digdiff.js example.com --dnssec # set the DO bit (EDNS0), ask for RRSIGs
```

Requires Node 18+ (uses `fetch`-free `https` + raw sockets — nothing to install).

### Options

| flag | meaning |
| --- | --- |
| `-t, --type` | record type: `A` (default), `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR`, `SRV` |
| `--doh` | also query DoH endpoints (cloudflare, google, quad9, adguard) |
| `--dnssec` | send the EDNS0 DO bit — ask resolvers to include DNSSEC records |
| `--nxdomain` | additionally probe a random `.invalid` name to catch NXDOMAIN hijacking |
| `--no-system` | skip the system resolvers |
| `--no-public` | skip the public UDP resolvers |
| `--json` | machine-readable output (for scripts, CI, dashboards) |

Exit codes: `0` everyone agrees, `1` someone disagrees or failed, `2` bad usage.

### JSON mode

```sh
node bin/digdiff.js github.com --json | jq '.results[] | select(.verdict != "agree")'
```

```json
{
  "name": "github.com",
  "type": "A",
  "consensus": false,
  "groundTruth": { "error": null, "answers": "140.82.121.3 140.82.121.4" },
  "results": [
    {
      "resolver": "quad9",
      "operator": "Quad9",
      "verdict": "differ",
      "majority": "140.82.121.3",
      "rcode": "NOERROR",
      "latencyMs": 71.6,
      "answers": "4.225.11.194",
      "error": null
    }
  ],
  "nxdomain": []
}
```

## How the verdict works

1. **Ground truth first.** digdiff finds the zone's nameservers (via the
   bootstrap resolver), resolves their addresses, and queries them directly
   for the record. Whatever the zone itself says is the baseline.
2. **Ask everyone.** Every selected resolver gets the same question over
   UDP (with TCP fallback on truncation — flag 0x0200), DoH ones over HTTPS.
3. **Corroborate.** Each answer value is counted across all resolvers plus
   the authoritative servers. An answer that only *one* source produced and
   the zone itself never serves is flagged:
   - `agree` — everything it said checks out (or matched NXDOMAIN)
   - `partial` — mixed bag: some answers corroborated, some not
   - `differ` — every answer is either made up or unique to this resolver
4. **NXDOMAIN probe** (`--nxdomain`): a random `.invalid` name *must not*
   exist. Any resolver returning an answer or a non-NXDOMAIN rcode for it is
   a hijacker by definition.

Without reachable authoritative servers (offline zone, weird TLDs) digdiff
falls back to a plain majority vote.

## Implementation notes

- `src/dns.js` — wire format: header, questions, compression-pointer-safe
  name decoding (bounded at 128 pointer jumps), A/AAAA/CNAME/NS/SOA/PTR/MX/
  TXT/SRV/OPT parsing.
- `src/transport.js` — UDP with a 3s timeout, TCP fallback with a 5s
  timeout for truncated responses, DoH via `application/dns-message` POST.
- `src/resolvers.js` — system resolver discovery via `scutil --dns`
  (macOS) with `/etc/resolv.conf` fallback; bundled public resolvers and
  DoH endpoints.
- `src/probe.js` — probing, latency measurement (`hrtime`), fingerprints,
  ground truth, and the corroboration-based judge.
- `bin/digdiff.js` — CLI (zero-dependency arg parsing via `node:util`),
  aligned table output, JSON mode.

All of it is plain Node built-ins — no `dns` module, no `net`-helpers, no
packages.

## Known limitations

- **Geo-rotating zones** (e.g. `google.com` AAAA): large providers serve
  different address subsets to different resolvers — perfectly legit, will
  show up as `differ`. Cross-check the actual addresses before panicking.
- **DNSSEC-validation state** is not verified (digdiff always sets the DO
  bit but doesn't validate RRSIGs vs. the trust chain — that's a resolver's
  job, and servers like Quad9 validate by default).
- One-shot nature: transient hijacking is intermittent by design — run a
  few times or script it with `--json` to build a history.

## License

MIT