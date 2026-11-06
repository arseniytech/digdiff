// The probe: fire the same question at every resolver in parallel, then
// compare what came back. A resolver that disagrees with the majority is
// either broken or lying — that's the whole project.

import { buildQuery, parseResponse, typeName, TYPE } from './dns.js';
import { query } from './transport.js';
import { PUBLIC_RESOLVERS } from './resolvers.js';

// One round-trip against one resolver.
export async function probeOne(resolver, name, qtype, { id, dnssec = false } = {}) {
  const buf = buildQuery(id, name, qtype, { edns: true, dnssec });
  const started = process.hrtime.bigint();
  const raw = await query(resolver, buf, id);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  const parsed = parseResponse(raw);
  return {
    resolver,
    name,
    qtype,
    latencyMs: Math.round(elapsedMs * 10) / 10,
    rcode: parsed.rcode,
    truncated: parsed.truncated,
    authenticated: parsed.authenticated,
    answers: parsed.answers.filter((a) => a.section === 'answer'),
  };
}

// Same id across resolvers isn't required by DNS but makes debugging nicer.
export async function probeAll(resolvers, name, qtype, opts = {}) {
  const id = (opts.id ?? Math.floor(Math.random() * 0xffff)) & 0xffff;
  const results = await Promise.allSettled(
    resolvers.map((r) => probeOne(r, name, qtype, { id, dnssec: opts.dnssec }))
  );
  return results.map((res, i) =>
    res.status === 'fulfilled'
      ? res.value
      : {
          resolver: resolvers[i],
          name,
          qtype,
          latencyMs: null,
          rcode: null,
          answers: [],
          error: res.reason.message,
        }
  );
}

// Ask the zone's own authoritative nameservers for the answer, skipping
// every recursive resolver in between. That gives us ground truth to judge
// the rest against — if someone answers differently, they're lying.
export async function fetchGroundTruth(name, qtype, { bootstrap = PUBLIC_RESOLVERS[0].address } = {}) {
  const nsId = Math.floor(Math.random() * 0xffff);
  let nsResp;
  try {
    nsResp = parseResponse(await query({ address: bootstrap, kind: 'udp' }, buildQuery(nsId, name, TYPE.NS), nsId));
  } catch (e) {
    return { answers: [], error: `ns lookup failed: ${e.message}` };
  }
  const nsTargets = nsResp.answers.filter((a) => a.type === TYPE.NS).map((a) => a.data.target);
  if (nsTargets.length === 0) return { answers: [], error: 'no NS records found' };

  // glue: ask bootstrap for each nameserver's address
  const ips = [];
  for (const ns of nsTargets.slice(0, 4)) {
    const aId = Math.floor(Math.random() * 0xffff);
    try {
      const aResp = parseResponse(await query({ address: bootstrap, kind: 'udp' }, buildQuery(aId, ns, TYPE.A), aId));
      for (const rr of aResp.answers) if (rr.data?.ipv4) ips.push({ ns, ip: rr.data.ipv4 });
    } catch { /* skip unresolvable ns */ }
  }
  if (ips.length === 0) return { answers: [], error: 'could not resolve any NS address' };

  const answers = [];
  const seen = new Set();
  // two rounds per nameserver: some zones rotate answers per query
  // (looking at you, google.com AAAA) — one shot would undersell the truth
  for (const { ns, ip } of ips) {
    for (let round = 0; round < 2; round++) {
      const gId = Math.floor(Math.random() * 0xffff);
      try {
        const gResp = parseResponse(await query({ address: ip, kind: 'udp' }, buildQuery(gId, name, qtype), gId));
        for (const rr of gResp.answers) {
          if (rr.section !== 'answer') continue;
          const key = JSON.stringify(rr.data) + rr.type;
          if (seen.has(key)) continue;
          seen.add(key);
          answers.push({ ns, ...rr });
        }
      } catch { /* a quiet nameserver is fine, others will answer */ }
    }
  }
  return { answers, error: answers.length ? null : 'authoritative servers returned nothing' };
}

// A compact fingerprint of what a resolver claimed: "1.2.3.4 5.6.7.8" or
// "cname:foo.example". Equal fingerprints = agreement.
export function fingerprint(results) {
  if (results.length === 0) return null;
  const parts = [];
  for (const r of results) {
    if (r.type === TYPE.CNAME || r.type === TYPE.NS || r.type === TYPE.PTR) {
      parts.push(`${typeName(r.type).toLowerCase()}:${r.data.target}`);
    } else if (r.data?.ipv4) {
      parts.push(r.data.ipv4);
    } else if (r.data?.ipv6) {
      parts.push(r.data.ipv6);
    } else if (r.data?.strings) {
      parts.push(`txt:${r.data.strings.join('')}`);
    } else if (r.data?.exchange) {
      parts.push(`mx:${r.data.preference} ${r.data.exchange}`);
    } else if (r.data?.raw) {
      parts.push(`raw:${r.data.raw}`);
    }
  }
  return [...new Set(parts)].sort().join(' ');
}

export function rcodeName(code) {
  const names = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];
  return names[code] ?? String(code);
}

// Verdict per resolver. With ground truth (authoritative answers) in hand we
// can be strict: a claim counts only if someone else — an authoritative
// server or another resolver — made it too. A resolver that returns answers
// nobody else can confirm is either broken or lying.
export function judge(results, groundTruth) {
  const truthParts = groundTruth && groundTruth.answers.length
    ? new Set((fingerprint(groundTruth.answers) ?? '').split(' ').filter(Boolean))
    : null;

  // every resolver's claimed answers, pooled by answer value
  const claimsByResolver = results.map((r) => {
    if (r.error || r.rcode === 3) return new Set();
    return new Set((fingerprint(r.answers) ?? '').split(' ').filter(Boolean));
  });
  // how many independent sources (resolvers + authoritative servers) saw
  // each answer — 1 means "only this resolver claimed it", >=2 means
  // someone else corroborates it
  const corroboration = new Map();
  for (const s of claimsByResolver) {
    for (const p of s) corroboration.set(p, (corroboration.get(p) ?? 0) + 1);
  }
  if (truthParts) {
    for (const p of truthParts) corroboration.set(p, (corroboration.get(p) ?? 0) + 1);
  }

  const votes = new Map();
  for (const r of results) {
    const key = r.error ? 'error' : r.rcode === 3 ? 'nxdomain' : fingerprint(r.answers) ?? 'no-answers';
    votes.set(key, (votes.get(key) ?? 0) + 1);
  }
  const majority = [...votes.entries()].sort((a, b) => b[1] - a[1])[0][0];

  return results.map((r, i) => {
    if (r.error) return { result: r, verdict: 'error', majority };
    const claimed = [...claimsByResolver[i]];
    let verdict;
    if (truthParts) {
      // an answer is a lie if nobody else saw it: count how many sources
      // corroborate each claim, and a resolver's own claim doesn't count
      const unknown = claimed.filter((p) => (corroboration.get(p) ?? 0) <= 1);
      if (claimed.length === 0 && r.rcode === 3) {
        verdict = 'agree'; // matching NXDOMAIN stays agreement
      } else if (unknown.length === 0) {
        verdict = 'agree';
      } else if (unknown.length < claimed.length) {
        verdict = 'partial'; // mixes corroborated answers with made-up ones
      } else {
        verdict = 'differ';
      }
    } else {
      // no ground truth — majority vote, NXDOMAINs always agree with each other
      const key = r.rcode === 3 ? 'nxdomain' : fingerprint(r.answers) ?? 'no-answers';
      verdict = key === majority ? 'agree' : 'differ';
    }
    return { result: r, verdict, majority };
  });
}